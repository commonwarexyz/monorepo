//! Deterministic scheduler for simulated message delivery with bandwidth limits.
//!
//! This module provides a scheduler that manages message transmission timing,
//! bandwidth allocation, and FIFO delivery ordering for simulated networks.

use super::bandwidth::{self, Flow, Rate};
use bytes::Bytes;
use commonware_utils::{time::SYSTEM_TIME_PRECISION, BigRationalExt, SystemTimeExt};
use num_rational::BigRational;
use num_traits::Zero;
use std::{
    collections::{btree_map::Entry, BTreeMap, VecDeque},
    fmt::Debug,
    time::{Duration, SystemTime},
};
use tracing::trace;

/// Message that is waiting to be delivered.
#[derive(Clone, Debug)]
pub struct Completion<P, C> {
    pub origin: P,
    pub recipient: P,
    pub channel: C,
    pub message: Bytes,
    pub deliver_at: Option<SystemTime>,
}

impl<P, C> Completion<P, C> {
    /// Creates a completion for a delivered message.
    const fn delivered(
        origin: P,
        recipient: P,
        channel: C,
        message: Bytes,
        deliver_at: SystemTime,
    ) -> Self {
        Self {
            origin,
            recipient,
            channel,
            message,
            deliver_at: Some(deliver_at),
        }
    }

    /// Creates a completion for a dropped message.
    const fn dropped(origin: P, recipient: P, channel: C, message: Bytes) -> Self {
        Self {
            origin,
            recipient,
            channel,
            message,
            deliver_at: None,
        }
    }
}

/// Message that has been buffered and will be delivered later.
#[derive(Clone, Debug)]
struct Buffered<C> {
    channel: C,
    message: Bytes,
    arrival_complete_at: SystemTime,
}

/// Message that is queued to be sent.
#[derive(Clone, Debug)]
struct Queued<C> {
    channel: C,
    message: Bytes,
    latency: Duration,
    should_deliver: bool,
    ready_at: Option<SystemTime>,
}

/// Bandwidth limits for a peer (bytes per second, `None` => unlimited).
#[derive(Clone, Debug)]
struct Bandwidth {
    egress: Option<u128>,
    ingress: Option<u128>,
}

/// Status of a flow (a single transmission request).
#[derive(Clone, Debug)]
struct Status<P, C> {
    origin: P,
    recipient: P,
    latency: Duration,
    channel: C,
    message: Bytes,
    sequence: Option<u128>, // delivered if some
    remaining: BigRational,
    rate: Rate,
    last_update: SystemTime,
}

/// Deterministic scheduler responsible for simulating link bandwidth and delivery ordering.
///
/// Orchestration overview:
/// - `enqueue` is the public entry point for sending; it records the request, then immediately
///   calls `launch`, which may start a new flow. When a flow is created, `begin` installs it and
///   invokes `rebalance` so the bandwidth planner can recompute rates.
/// - The runtime drives progression with `next`/`advance`. `next` reports the earlier of the
///   next bandwidth event or transmission-ready time. `advance(now)` first `wake`s transmissions
///   whose start time has arrived, then keeps draining events occurring at `now`. Inside this loop
///   `rebalance` advances active flows and calls `finish` on completions, while another `wake`
///   handles newly eligible queued work.
/// - `finish` produces `Completion`s (via `stash` + `drain`) and immediately tries to `launch` the
///   next queued message for that peer pair, allowing back-to-back transmissions without waiting
///   for another outer tick. `schedule` keeps track of the earliest queued start time so `next`
///   always reflects both bandwidth expiries and queue readiness.
///
/// # Type Parameters
///
/// - `P`: Peer identifier type (e.g., `PublicKey`, `Ipv4Addr`, or any `Clone + Ord + Debug` type)
/// - `C`: Channel identifier type (e.g., `u32` or any `Clone + Ord + Debug` type)
pub struct State<P, C> {
    bandwidth_caps: BTreeMap<P, Bandwidth>,
    next_flow_id: u64,
    assign_sequences: BTreeMap<(P, P), u128>,
    active_flows: BTreeMap<(P, P), u64>,
    all_flows: BTreeMap<u64, Status<P, C>>,
    queued: BTreeMap<(P, P), VecDeque<Queued<C>>>,
    last_arrival_complete: BTreeMap<(P, P), SystemTime>,
    next_bandwidth_event: Option<SystemTime>,
    next_transmission_ready: Option<SystemTime>,
    expected_sequences: BTreeMap<(P, P), u128>,
    buffered: BTreeMap<(P, P), BTreeMap<u128, Buffered<C>>>,
}

impl<P: Clone + Ord + Debug, C: Clone + Debug> State<P, C> {
    /// Creates a new scheduler.
    pub const fn new() -> Self {
        Self {
            bandwidth_caps: BTreeMap::new(),
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
    pub fn limit(
        &mut self,
        now: SystemTime,
        peer: &P,
        egress: Option<usize>,
        ingress: Option<usize>,
    ) -> Vec<Completion<P, C>> {
        // Update bandwidth limits
        self.bandwidth_caps.insert(
            peer.clone(),
            Bandwidth {
                egress: egress.map(|bps| bps as u128),
                ingress: ingress.map(|bps| bps as u128),
            },
        );

        // Attempt to rebalance flows
        if self.all_flows.is_empty() {
            self.schedule(now);
            return Vec::new();
        }
        self.rebalance(now)
    }

    /// Returns the egress bandwidth limit for `peer`.
    fn egress_cap(&self, peer: &P) -> Option<u128> {
        self.bandwidth_caps
            .get(peer)
            .and_then(|limits| limits.egress)
    }

    /// Returns the ingress bandwidth limit for `peer`.
    fn ingress_cap(&self, peer: &P) -> Option<u128> {
        self.bandwidth_caps
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
    pub fn advance(&mut self, now: SystemTime) -> Vec<Completion<P, C>> {
        // Process all events until we arrive at now
        let mut completions = Vec::new();
        loop {
            let next_bandwidth = self.next_bandwidth_event.filter(|event| *event <= now);
            let next_ready = self.next_transmission_ready.filter(|event| *event <= now);

            match (next_bandwidth, next_ready) {
                (None, None) => break,
                (Some(band), Some(ready)) => {
                    if band <= ready {
                        self.next_bandwidth_event = None;
                        completions.extend(self.rebalance(band));
                    } else {
                        self.next_transmission_ready = None;
                        completions.extend(self.wake(ready));
                    }
                }
                (Some(band), None) => {
                    self.next_bandwidth_event = None;
                    completions.extend(self.rebalance(band));
                }
                (None, Some(ready)) => {
                    self.next_transmission_ready = None;
                    completions.extend(self.wake(ready));
                }
            }
        }

        // Wake explicitly at now
        completions.extend(self.wake(now));

        completions
    }

    /// Enqueue a message for transmission.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue(
        &mut self,
        now: SystemTime,
        origin: P,
        recipient: P,
        channel: C,
        message: Bytes,
        latency: Duration,
        should_deliver: bool,
    ) -> Vec<Completion<P, C>> {
        if self.bandwidth_caps.is_empty() {
            return self.fulfill_unconstrained(
                now,
                origin,
                recipient,
                channel,
                message,
                latency,
                should_deliver,
            );
        }

        let key = (origin.clone(), recipient.clone());
        let entry = Queued {
            channel,
            message,
            latency,
            should_deliver,
            ready_at: None,
        };

        self.queued.entry(key).or_default().push_back(entry);

        let completions = self.launch(origin, recipient, now);
        self.schedule(now);

        completions
    }

    /// Completes a transmission immediately when no bandwidth constraints are registered.
    #[allow(clippy::too_many_arguments)]
    fn fulfill_unconstrained(
        &mut self,
        now: SystemTime,
        origin: P,
        recipient: P,
        channel: C,
        message: Bytes,
        latency: Duration,
        should_deliver: bool,
    ) -> Vec<Completion<P, C>> {
        let key = (origin.clone(), recipient.clone());
        let last_arrival = self.last_arrival_complete.get(&key).cloned();

        let completions = if should_deliver {
            let ready_at = Self::compute_ready_at(None, now, last_arrival, latency);
            let arrival_complete_at = ready_at
                .checked_add(latency)
                .expect("latency overflow computing arrival completion");
            let sequence = Some(self.increment(&origin, &recipient));
            self.register_completion(
                origin,
                recipient,
                channel,
                message,
                arrival_complete_at,
                sequence,
            )
        } else {
            self.register_completion(origin, recipient, channel, message, now, None)
        };

        self.next_bandwidth_event = None;
        self.schedule(now);

        completions
    }

    /// Computes the time at which the message can start being sent.
    fn compute_ready_at(
        stored: Option<SystemTime>,
        now: SystemTime,
        last_arrival_complete: Option<SystemTime>,
        latency: Duration,
    ) -> SystemTime {
        let mut ready_at = stored.unwrap_or(now).max(now);
        if let Some(arrival_complete) = last_arrival_complete {
            // If there was a previously broadcast message, we need to respect its arrival time.
            if let Some(limit) = arrival_complete.checked_sub(latency) {
                ready_at = ready_at.max(limit);
            }
        }
        ready_at
    }

    /// Refresh the time at which the front of the queue can be sent.
    fn refresh_front_ready_at(
        queue: &mut VecDeque<Queued<C>>,
        now: SystemTime,
        last_arrival_complete: Option<SystemTime>,
    ) -> Option<SystemTime> {
        let front = queue.front_mut()?;
        let stored = front.ready_at;
        let ready_at = Self::compute_ready_at(stored, now, last_arrival_complete, front.latency);
        if ready_at <= now {
            front.ready_at = None;
        } else {
            front.ready_at = Some(ready_at);
        }
        Some(ready_at)
    }

    /// Awakens any queued transmissions that have become ready to send at `now`.
    fn wake(&mut self, now: SystemTime) -> Vec<Completion<P, C>> {
        // Collect all queued keys
        let queued_keys: Vec<(P, P)> = self.queued.keys().cloned().collect();

        // Check the ready_at values for each queued item
        let mut ready_pairs = Vec::new();
        for key in queued_keys {
            if self.active_flows.contains_key(&key) {
                continue;
            }

            let last_arrival = self.last_arrival_complete.get(&key).cloned();
            let Some(queue) = self.queued.get_mut(&key) else {
                continue;
            };

            if let Some(ready_at) = Self::refresh_front_ready_at(queue, now, last_arrival) {
                if ready_at <= now {
                    ready_pairs.push(key.clone());
                }
            }
        }

        // Launch any queued transmissions that have become ready to send at `now`
        let mut completions = Vec::new();
        for (origin, recipient) in ready_pairs {
            completions.extend(self.launch(origin, recipient, now));
        }
        self.schedule(now);

        completions
    }

    /// Recomputes bandwidth allocations and collects any flows that finished in the interval.
    fn rebalance(&mut self, now: SystemTime) -> Vec<Completion<P, C>> {
        let mut completed = Vec::new();
        let mut active: Vec<Flow<P>> = Vec::new();
        for (&flow_id, meta) in self.all_flows.iter_mut() {
            // Account for bytes already in flight since the last tick
            if !meta.remaining.is_zero() {
                let elapsed = now
                    .duration_since(meta.last_update)
                    .unwrap_or(Duration::ZERO);
                if !elapsed.is_zero() {
                    meta.remaining =
                        bandwidth::transfer(&meta.rate, elapsed, meta.remaining.clone());
                }
            }

            meta.last_update = now;
            if meta.remaining.is_zero() {
                completed.push(flow_id);
            } else {
                active.push(Flow {
                    id: flow_id,
                    origin: meta.origin.clone(),
                    recipient: meta.recipient.clone(),
                    delivered: meta.sequence.is_some(),
                });
            }
        }
        if active.is_empty() {
            self.next_bandwidth_event = None;
            return self.finish(completed, now);
        }

        let mut egress_cap = |pk: &P| self.egress_cap(pk);
        let mut ingress_cap = |pk: &P| self.ingress_cap(pk);
        let allocations = bandwidth::allocate(&active, &mut egress_cap, &mut ingress_cap);
        let mut earliest: Option<Duration> = None;
        for (flow_id, rate) in allocations {
            if let Some(meta) = self.all_flows.get_mut(&flow_id) {
                meta.rate = rate.clone();
                meta.last_update = now;

                if matches!(meta.rate, Rate::Unlimited) {
                    if !meta.remaining.is_zero() {
                        meta.remaining = BigRational::zero();
                        completed.push(flow_id);
                    }
                    continue;
                }

                if let Some(duration) = bandwidth::duration(&meta.rate, &meta.remaining) {
                    // Ensure the scheduled event advances by at least the platform precision so
                    // `SystemTime` actually moves forward on coarse clocks (e.g. Windows).
                    let duration = if duration.is_zero() {
                        Duration::ZERO
                    } else {
                        duration.max(SYSTEM_TIME_PRECISION)
                    };
                    earliest =
                        earliest.map_or(Some(duration), |current| Some(current.min(duration)));
                }
            }
        }
        completed.sort();

        // Record the next time at which a bandwidth event should fire.
        self.next_bandwidth_event = earliest.map(|duration| now.saturating_add(duration));

        self.finish(completed, now)
    }

    /// Finalizes completed flows and opportunistically starts follow-on work.
    fn finish(&mut self, completed: Vec<u64>, now: SystemTime) -> Vec<Completion<P, C>> {
        let mut outcomes = Vec::new();

        for flow_id in completed {
            // Skip any flows that have already been removed
            let Some(meta) = self.all_flows.remove(&flow_id) else {
                continue;
            };

            let Status {
                origin,
                recipient,
                latency,
                channel,
                message,
                sequence,
                ..
            } = meta;

            let key = (origin.clone(), recipient.clone());
            self.active_flows.remove(&key);

            let arrival_complete_at = if sequence.is_some() {
                now.checked_add(latency)
                    .expect("latency overflow computing arrival completion")
            } else {
                now
            };

            outcomes.extend(self.register_completion(
                origin.clone(),
                recipient.clone(),
                channel,
                message,
                arrival_complete_at,
                sequence,
            ));

            outcomes.extend(self.launch(origin, recipient, now));
        }
        self.schedule(now);

        outcomes
    }

    /// Records the outcome of a transmission, handling sequencing and delivery bookkeeping.
    #[allow(clippy::too_many_arguments)]
    fn register_completion(
        &mut self,
        origin: P,
        recipient: P,
        channel: C,
        message: Bytes,
        arrival_complete_at: SystemTime,
        sequence: Option<u128>,
    ) -> Vec<Completion<P, C>> {
        let key = (origin.clone(), recipient.clone());
        self.last_arrival_complete.insert(key, arrival_complete_at);

        if let Some(seq) = sequence {
            let buffered = Buffered {
                channel,
                message,
                arrival_complete_at,
            };
            self.stash(origin, recipient, seq, buffered)
        } else {
            trace!(
                ?origin,
                ?recipient,
                reason = "random link failure",
                "dropping message",
            );
            vec![Completion::dropped(origin, recipient, channel, message)]
        }
    }

    /// Buffers an arrival until preceding transmissions are released.
    fn stash(
        &mut self,
        origin: P,
        recipient: P,
        seq: u128,
        buffered: Buffered<C>,
    ) -> Vec<Completion<P, C>> {
        let key = (origin, recipient);
        self.buffered
            .entry(key.clone())
            .or_default()
            .insert(seq, buffered);
        self.drain(key)
    }

    /// Emits any pending deliveries for the given pair whose sequence is now in order.
    fn drain(&mut self, key: (P, P)) -> Vec<Completion<P, C>> {
        let expected_entry = self.expected_sequences.entry(key.clone()).or_insert(0);
        let mut delivered = Vec::new();

        loop {
            let buffered = match self.buffered.entry(key.clone()) {
                Entry::Occupied(mut occ) => occ.get_mut().remove(expected_entry).inspect(|_| {
                    if occ.get().is_empty() {
                        occ.remove();
                    }
                }),
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
        // Collect all queued keys
        let queued_keys: Vec<(P, P)> = self.queued.keys().cloned().collect();

        // Check the ready_at values for each queued item
        let mut next_ready: Option<SystemTime> = None;
        for key in queued_keys {
            if self.active_flows.contains_key(&key) {
                continue;
            }

            let last_arrival = self.last_arrival_complete.get(&key).cloned();
            let Some(queue) = self.queued.get_mut(&key) else {
                continue;
            };

            if let Some(ready_at) = Self::refresh_front_ready_at(queue, now, last_arrival) {
                let candidate = if ready_at <= now { now } else { ready_at };
                next_ready =
                    next_ready.map_or(Some(candidate), |current| Some(current.min(candidate)));
            }
        }

        self.next_transmission_ready = next_ready;
    }

    /// Attempts to start a new flow for the pair, optionally refreshing scheduling metadata.
    fn launch(&mut self, origin: P, recipient: P, now: SystemTime) -> Vec<Completion<P, C>> {
        let key = (origin.clone(), recipient.clone());
        if self.active_flows.contains_key(&key) {
            return Vec::new();
        }

        let mut entry_to_start = None;
        let mut remove_queue = false;

        if let Some(queue) = self.queued.get_mut(&key) {
            let last_arrival = self.last_arrival_complete.get(&key).cloned();
            match Self::refresh_front_ready_at(queue, now, last_arrival) {
                Some(ready_at) if ready_at <= now => {
                    entry_to_start = queue.pop_front();
                    if queue.is_empty() {
                        remove_queue = true;
                    }
                }
                Some(_) => {}
                None => {
                    remove_queue = true;
                }
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
        entry: Queued<C>,
        now: SystemTime,
    ) -> Vec<Completion<P, C>> {
        let Queued {
            channel,
            message,
            latency,
            should_deliver,
            ..
        } = entry;

        let deliver = should_deliver && origin != recipient;
        let remaining = BigRational::from_usize(message.len());
        let sequence = if deliver {
            Some(self.increment(&origin, &recipient))
        } else {
            None
        };

        self.all_flows.insert(
            flow_id,
            Status {
                origin: origin.clone(),
                recipient: recipient.clone(),
                latency,
                channel,
                message,
                sequence,
                remaining,
                rate: Rate::Finite(BigRational::zero()),
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
    fn increment(&mut self, origin: &P, recipient: &P) -> u128 {
        let key = (origin.clone(), recipient.clone());
        let counter = self.assign_sequences.entry(key).or_insert(0);
        let seq = *counter;
        *counter += 1;
        seq
    }
}

impl<P: Clone + Ord + Debug, C: Clone + Debug> Default for State<P, C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    // Use simple integers as peer identifiers for testing
    type TestState = State<u64, u32>;

    const CHANNEL: u32 = 0;

    #[test]
    fn queue_immediate_completion_with_unlimited_capacity() {
        let mut state = TestState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = 1u64;
        let recipient = 2u64;

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
        assert_eq!(completion.deliver_at, Some(now));
    }

    #[test]
    fn queue_dropped_message_records_outcome() {
        let mut state = TestState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = 3u64;
        let recipient = 4u64;

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
        assert!(completions[0].deliver_at.is_none());
    }

    #[test]
    fn rebalance_schedules_event_for_huge_transfers() {
        let mut state = TestState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = 20u64;
        let recipient = 21u64;

        // Configure bandwidth constraints so the flow is limited by both peers.
        assert!(state.limit(now, &origin, Some(1), None).is_empty());
        assert!(state.limit(now, &recipient, None, Some(1)).is_empty());

        // Enqueue a small message to create the flow entry.
        let completions = state.enqueue(
            now,
            origin,
            recipient,
            CHANNEL,
            Bytes::from_static(b"x"),
            Duration::ZERO,
            true,
        );
        assert!(completions.is_empty());

        // Rebalance to schedule the bandwidth event
        let _ = state.rebalance(now);
        assert!(state.next().is_some(), "bandwidth event must be scheduled");
    }

    #[test]
    fn fifo_delivery_per_pair() {
        let mut state = TestState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = 10u64;
        let recipient = 11u64;
        let make_bytes = |value: u8| Bytes::from(vec![value; 1_000]);

        let completions = state.limit(now, &origin, Some(1_000), None);
        assert!(completions.is_empty());

        let completions = state.enqueue(
            now,
            origin,
            recipient,
            CHANNEL,
            make_bytes(1),
            Duration::from_secs(1),
            true,
        );
        assert!(completions.is_empty());

        let first_finish = state.next().expect("first completion scheduled");
        assert_eq!(first_finish, now + Duration::from_secs(1));

        let completions = state.advance(first_finish);
        assert_eq!(completions.len(), 1);
        let completion_a = &completions[0];
        assert_eq!(
            completion_a.deliver_at,
            Some(first_finish + Duration::from_secs(1))
        );

        let completions = state.enqueue(
            now,
            origin,
            recipient,
            CHANNEL,
            make_bytes(2),
            Duration::ZERO,
            true,
        );
        assert!(completions.is_empty());

        let completions = state.advance(now);
        assert!(completions.is_empty());

        let next_ready = state.next().expect("second transfer should be scheduled");
        assert_eq!(next_ready, first_finish + Duration::from_secs(1));

        let completions = state.advance(next_ready);
        assert!(completions.is_empty());

        let second_finish = state.next().expect("second completion scheduled");
        assert_eq!(second_finish, next_ready + Duration::from_secs(1));

        let completions = state.advance(second_finish);
        assert_eq!(completions.len(), 1);
        let completion_b = &completions[0];
        assert_eq!(completion_b.deliver_at, Some(second_finish));
        assert_eq!(completion_b.message.len(), 1_000);
        assert_eq!(completion_b.message[0], 2);
    }

    #[test]
    fn unconstrained_delivery_is_immediate() {
        let mut state = TestState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = 46u64;
        let recipient = 47u64;

        let completions = state.enqueue(
            now,
            origin,
            recipient,
            CHANNEL,
            Bytes::from_static(b"first"),
            Duration::from_millis(100),
            true,
        );
        assert_eq!(completions.len(), 1);
        assert_eq!(
            completions[0].deliver_at,
            Some(now + Duration::from_millis(100))
        );

        let completions = state.enqueue(
            now,
            origin,
            recipient,
            CHANNEL,
            Bytes::from_static(b"second"),
            Duration::from_millis(50),
            true,
        );
        assert_eq!(completions.len(), 1);
        assert_eq!(
            completions[0].deliver_at,
            Some(now + Duration::from_millis(100)) // must still be FIFO
        );

        assert!(state.next().is_none());
    }

    #[test]
    fn equal_split_across_destinations() {
        let mut state = TestState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = 30u64;
        let recipient_b = 31u64;
        let recipient_c = 32u64;

        let completions = state.limit(now, &origin, Some(1_000), None);
        assert!(completions.is_empty());

        let msg_b = Bytes::from(vec![0xBB; 1_000]);
        let msg_c = Bytes::from(vec![0xCC; 1_000]);

        let completions = state.enqueue(
            now,
            origin,
            recipient_b,
            CHANNEL,
            msg_b,
            Duration::ZERO,
            true,
        );
        assert!(completions.is_empty());

        let completions = state.enqueue(
            now,
            origin,
            recipient_c,
            CHANNEL,
            msg_c,
            Duration::ZERO,
            true,
        );
        assert!(completions.is_empty());

        let finish = state.next().expect("completion scheduled");
        assert_eq!(finish, now + Duration::from_secs(2));

        let completions = state.advance(finish);
        assert_eq!(completions.len(), 2);

        let mut recipients: Vec<_> = completions
            .iter()
            .map(|c| {
                assert_eq!(c.message.len(), 1_000);
                assert_eq!(c.deliver_at, Some(finish));
                c.recipient
            })
            .collect();
        recipients.sort();
        let mut expected = vec![recipient_b, recipient_c];
        expected.sort();
        assert_eq!(recipients, expected);

        assert!(state.next().is_none());
    }

    #[test]
    fn advancing_long_after_next_drains_once() {
        let mut state = TestState::new();
        let start = SystemTime::UNIX_EPOCH;
        let origin = 42u64;
        let recipient = 43u64;

        let completions = state.limit(start, &origin, Some(1_000), None);
        assert!(completions.is_empty());

        state.enqueue(
            start,
            origin,
            recipient,
            CHANNEL,
            Bytes::from_static(&[7u8; 1_000]),
            Duration::from_millis(250),
            true,
        );

        let first_deadline = state.next().expect("bandwidth event scheduled");
        assert_eq!(first_deadline, start + Duration::from_secs(1));

        let late_time = first_deadline + Duration::from_secs(5);
        let completions = state.advance(late_time);
        assert_eq!(completions.len(), 1);

        let completion = &completions[0];
        assert_eq!(completion.origin, origin);
        assert_eq!(completion.recipient, recipient);
        assert_eq!(
            completion.deliver_at,
            Some(first_deadline + Duration::from_millis(250))
        );

        assert!(state.next().is_none());

        let more = state.advance(late_time + Duration::from_secs(1));
        assert!(more.is_empty());
    }

    #[test]
    fn advancing_to_past_instants_is_noop() {
        let mut state = TestState::new();
        let start = SystemTime::UNIX_EPOCH;
        let origin = 44u64;
        let recipient = 45u64;

        let completions = state.limit(start, &origin, Some(1_000), None);
        assert!(completions.is_empty());

        state.enqueue(
            start,
            origin,
            recipient,
            CHANNEL,
            Bytes::from_static(&[0xAB; 1_000]),
            Duration::ZERO,
            true,
        );

        let deadline = state.next().expect("completion scheduled");
        let completions = state.advance(deadline);
        assert_eq!(completions.len(), 1);
        assert!(completions[0].deliver_at.is_some());

        let more = state.advance(deadline);
        assert!(more.is_empty());

        let more = state.advance(UNIX_EPOCH);
        assert!(more.is_empty());
    }

    #[test]
    fn refresh_rebalances_active_flow() {
        let mut state = TestState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = 50u64;
        let recipient = 51u64;

        let completions = state.limit(now, &origin, Some(1_000), None); // 1 KB/s egress
        assert!(completions.is_empty());

        let msg = Bytes::from(vec![0xDD; 1_000]);
        let completions = state.enqueue(
            now,
            origin,
            recipient,
            CHANNEL,
            msg.clone(),
            Duration::ZERO,
            true,
        );
        assert!(completions.is_empty());

        let finish = state
            .next()
            .expect("completion scheduled under limited bandwidth");
        assert_eq!(finish, now + Duration::from_secs(1));

        let completions = state.limit(now, &origin, None, None); // unlimited egress
        assert_eq!(completions.len(), 1);
        let completion = &completions[0];
        assert_eq!(completion.message.len(), msg.len());
        assert_eq!(completion.deliver_at, Some(now));

        assert!(state.next().is_none());
    }
}
