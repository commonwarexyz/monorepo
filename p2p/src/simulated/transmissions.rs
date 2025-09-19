use super::bandwidth::{self, Flow, FlowRate};
use crate::Channel;
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_utils::math::u128::Ratio;
use std::{
    collections::{btree_map::Entry, BTreeMap, VecDeque},
    time::{Duration, SystemTime},
};
use tracing::trace;

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

#[derive(Clone, Debug)]
struct PendingDelivery {
    channel: Channel,
    message: Bytes,
    arrival_complete_at: SystemTime,
}

#[derive(Clone, Debug)]
struct QueuedTransmission {
    channel: Channel,
    message: Bytes,
    latency: Duration,
    should_deliver: bool,
    ready_at: SystemTime,
}

#[derive(Clone, Debug)]
struct FlowMeta<P: PublicKey> {
    origin: P,
    recipient: P,
    latency: Duration,
    deliver: bool,
    channel: Channel,
    message: Bytes,
    sequence: Option<u64>,
    remaining: u128,
    rate: FlowRate,
    carry: u128,
    last_update: SystemTime,
}

pub struct TransmissionState<P: PublicKey + Ord + Clone> {
    next_flow_id: u64,
    assign_sequences: BTreeMap<(P, P), u64>,
    active_flows: BTreeMap<(P, P), u64>,
    flow_meta: BTreeMap<u64, FlowMeta<P>>,
    pending_transmissions: BTreeMap<(P, P), VecDeque<QueuedTransmission>>,
    last_arrival_complete: BTreeMap<(P, P), SystemTime>,
    next_bandwidth_event: Option<SystemTime>,
    next_transmission_ready: Option<SystemTime>,
    expected_sequences: BTreeMap<(P, P), u64>,
    pending_deliveries: BTreeMap<(P, P), BTreeMap<u64, PendingDelivery>>,
}

impl<P: PublicKey + Ord + Clone> TransmissionState<P> {
    pub fn new() -> Self {
        Self {
            next_flow_id: 0,
            assign_sequences: BTreeMap::new(),
            active_flows: BTreeMap::new(),
            flow_meta: BTreeMap::new(),
            pending_transmissions: BTreeMap::new(),
            last_arrival_complete: BTreeMap::new(),
            next_bandwidth_event: None,
            next_transmission_ready: None,
            expected_sequences: BTreeMap::new(),
            pending_deliveries: BTreeMap::new(),
        }
    }

    pub fn next_bandwidth_event(&self) -> Option<SystemTime> {
        self.next_bandwidth_event
    }

    pub fn clear_next_bandwidth_event(&mut self) {
        self.next_bandwidth_event = None;
    }

    pub fn next_transmission_ready(&self) -> Option<SystemTime> {
        self.next_transmission_ready
    }

    pub fn clear_next_transmission_ready(&mut self) {
        self.next_transmission_ready = None;
    }

    pub fn queue_transmission<F, G>(
        &mut self,
        now: SystemTime,
        origin: P,
        recipient: P,
        channel: Channel,
        message: Bytes,
        latency: Duration,
        should_deliver: bool,
        egress_limit: &mut F,
        ingress_limit: &mut G,
    ) -> Vec<Completion<P>>
    where
        F: FnMut(&P) -> Option<u128>,
        G: FnMut(&P) -> Option<u128>,
    {
        let key = (origin.clone(), recipient.clone());
        let mut entry = QueuedTransmission {
            channel,
            message,
            latency,
            should_deliver,
            ready_at: now,
        };

        entry.ready_at = entry.ready_at.max(now);
        if let Some(arrival_complete) = self.last_arrival_complete.get(&key) {
            if let Some(limit) = arrival_complete.checked_sub(entry.latency) {
                entry.ready_at = entry.ready_at.max(limit);
            }
        }
        self.pending_transmissions
            .entry(key.clone())
            .or_default()
            .push_back(entry);

        self.try_start_transmission_for(origin, recipient, true, now, egress_limit, ingress_limit)
    }

    pub fn start_due_transmissions<F, G>(
        &mut self,
        now: SystemTime,
        egress_limit: &mut F,
        ingress_limit: &mut G,
    ) -> Vec<Completion<P>>
    where
        F: FnMut(&P) -> Option<u128>,
        G: FnMut(&P) -> Option<u128>,
    {
        let ready_pairs: Vec<(P, P)> = self
            .pending_transmissions
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
            completions.extend(self.try_start_transmission_for(
                origin,
                recipient,
                false,
                now,
                egress_limit,
                ingress_limit,
            ));
        }
        self.refresh_next_transmission_ready(now);
        completions
    }

    pub fn recompute_bandwidth<F, G>(
        &mut self,
        now: SystemTime,
        egress_limit: &mut F,
        ingress_limit: &mut G,
    ) -> Vec<Completion<P>>
    where
        F: FnMut(&P) -> Option<u128>,
        G: FnMut(&P) -> Option<u128>,
    {
        let mut completed = Vec::new();

        for (&flow_id, meta) in self.flow_meta.iter_mut() {
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

        completed.sort_unstable();
        completed.dedup();

        let mut active: Vec<Flow<P>> = Vec::new();
        for (&flow_id, meta) in self.flow_meta.iter() {
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
            return self.handle_completed_flows(completed, now, egress_limit, ingress_limit);
        }

        let allocations = bandwidth::allocate(&active, &mut *egress_limit, &mut *ingress_limit);
        let mut earliest: Option<Duration> = None;

        for (flow_id, rate) in allocations {
            if let Some(meta) = self.flow_meta.get_mut(&flow_id) {
                meta.rate = rate.clone();
                meta.carry = 0;
                meta.last_update = now;

                if matches!(meta.rate, FlowRate::Unlimited) {
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

        completed.sort_unstable();
        completed.dedup();

        self.next_bandwidth_event = earliest.and_then(|duration| {
            if duration.is_zero() {
                Some(now)
            } else {
                now.checked_add(duration)
            }
        });

        self.handle_completed_flows(completed, now, egress_limit, ingress_limit)
    }

    pub fn handle_completed_flows<F, G>(
        &mut self,
        completed: Vec<u64>,
        now: SystemTime,
        egress_limit: &mut F,
        ingress_limit: &mut G,
    ) -> Vec<Completion<P>>
    where
        F: FnMut(&P) -> Option<u128>,
        G: FnMut(&P) -> Option<u128>,
    {
        let mut outcomes = Vec::new();

        for flow_id in completed {
            let Some(meta) = self.flow_meta.remove(&flow_id) else {
                continue;
            };

            let FlowMeta {
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
                    let pending = PendingDelivery {
                        channel,
                        message,
                        arrival_complete_at,
                    };
                    outcomes.extend(self.enqueue_delivery(
                        origin.clone(),
                        recipient.clone(),
                        seq,
                        pending,
                    ));
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

            outcomes.extend(self.try_start_transmission_for(
                origin,
                recipient,
                true,
                now,
                egress_limit,
                ingress_limit,
            ));
        }

        outcomes
    }

    fn enqueue_delivery(
        &mut self,
        origin: P,
        recipient: P,
        seq: u64,
        pending: PendingDelivery,
    ) -> Vec<Completion<P>> {
        let key = (origin.clone(), recipient.clone());
        self.pending_deliveries
            .entry(key.clone())
            .or_default()
            .insert(seq, pending);
        self.flush_delivery_queue(key)
    }

    fn flush_delivery_queue(&mut self, key: (P, P)) -> Vec<Completion<P>> {
        let expected_entry = self.expected_sequences.entry(key.clone()).or_insert(0);
        let mut delivered = Vec::new();

        loop {
            let pending = match self.pending_deliveries.entry(key.clone()) {
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

            let Some(pending) = pending else { break };

            delivered.push(Completion::delivered(
                key.0.clone(),
                key.1.clone(),
                pending.channel,
                pending.message,
                pending.arrival_complete_at,
            ));

            *expected_entry += 1;
        }

        delivered
    }

    fn refresh_next_transmission_ready(&mut self, now: SystemTime) {
        let mut next_ready: Option<SystemTime> = None;
        for (key, queue) in self.pending_transmissions.iter() {
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

    fn try_start_transmission_for<F, G>(
        &mut self,
        origin: P,
        recipient: P,
        refresh_schedule: bool,
        now: SystemTime,
        egress_limit: &mut F,
        ingress_limit: &mut G,
    ) -> Vec<Completion<P>>
    where
        F: FnMut(&P) -> Option<u128>,
        G: FnMut(&P) -> Option<u128>,
    {
        let key = (origin.clone(), recipient.clone());
        if self.active_flows.contains_key(&key) {
            if refresh_schedule {
                self.refresh_next_transmission_ready(now);
            }
            return Vec::new();
        }

        let mut entry_to_start = None;
        let mut remove_queue = false;

        if let Some(queue) = self.pending_transmissions.get_mut(&key) {
            if let Some(front) = queue.front_mut() {
                let mut ready_at = front.ready_at.max(now);
                if let Some(arrival_complete) = self.last_arrival_complete.get(&key) {
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
            self.pending_transmissions.remove(&key);
        }

        if let Some(entry) = entry_to_start {
            let flow_id = self.next_flow_id;
            self.next_flow_id += 1;
            self.active_flows.insert(key, flow_id);
            return self.start_transmission(
                origin,
                recipient,
                flow_id,
                entry,
                now,
                egress_limit,
                ingress_limit,
            );
        }

        if refresh_schedule {
            self.refresh_next_transmission_ready(now);
        }

        Vec::new()
    }

    fn start_transmission<F, G>(
        &mut self,
        origin: P,
        recipient: P,
        flow_id: u64,
        entry: QueuedTransmission,
        now: SystemTime,
        egress_limit: &mut F,
        ingress_limit: &mut G,
    ) -> Vec<Completion<P>>
    where
        F: FnMut(&P) -> Option<u128>,
        G: FnMut(&P) -> Option<u128>,
    {
        let QueuedTransmission {
            channel,
            message,
            latency,
            should_deliver,
            ..
        } = entry;

        let deliver = should_deliver && origin != recipient;
        let remaining = message.len() as u128;
        let sequence = if deliver {
            Some(self.next_sequence_id(&origin, &recipient))
        } else {
            None
        };

        self.flow_meta.insert(
            flow_id,
            FlowMeta {
                origin: origin.clone(),
                recipient: recipient.clone(),
                latency,
                deliver,
                channel,
                message,
                sequence,
                remaining,
                rate: FlowRate::Finite(Ratio::zero()),
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

        let completions = self.recompute_bandwidth(now, egress_limit, ingress_limit);
        self.refresh_next_transmission_ready(now);
        completions
    }

    fn next_sequence_id(&mut self, origin: &P, recipient: &P) -> u64 {
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

    fn unlimited() -> impl FnMut(&ed25519::PublicKey) -> Option<u128> {
        |_pk| None
    }

    #[test]
    fn queue_immediate_completion_with_unlimited_capacity() {
        let mut state = TransmissionState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = key(1);
        let recipient = key(2);
        let mut egress = unlimited();
        let mut ingress = unlimited();

        let completions = state.queue_transmission(
            now,
            origin,
            recipient,
            CHANNEL,
            Bytes::from_static(b"hello"),
            Duration::ZERO,
            true,
            &mut egress,
            &mut ingress,
        );

        assert_eq!(completions.len(), 1);
        let completion = &completions[0];
        assert!(completion.deliver);
        assert_eq!(completion.arrival_complete_at, Some(now));
    }

    #[test]
    fn queue_dropped_message_records_outcome() {
        let mut state = TransmissionState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = key(3);
        let recipient = key(4);
        let mut egress = unlimited();
        let mut ingress = unlimited();

        let completions = state.queue_transmission(
            now,
            origin,
            recipient,
            CHANNEL,
            Bytes::from_static(b"drop"),
            Duration::ZERO,
            false,
            &mut egress,
            &mut ingress,
        );

        assert_eq!(completions.len(), 1);
        assert!(!completions[0].deliver);
        assert!(completions[0].arrival_complete_at.is_none());
    }

    #[test]
    fn fifo_delivery_per_pair() {
        let mut state = TransmissionState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = key(10);
        let recipient = key(11);
        let make_bytes = |value: u8| Bytes::from(vec![value; 1_000]);

        let mut egress_cap = |_pk: &ed25519::PublicKey| Some(1_000u128);
        let mut ingress_unlimited = unlimited();

        let completions = state.queue_transmission(
            now,
            origin.clone(),
            recipient.clone(),
            CHANNEL,
            make_bytes(1),
            Duration::ZERO,
            true,
            &mut egress_cap,
            &mut ingress_unlimited,
        );
        assert!(completions.is_empty());

        let first_finish = state
            .next_bandwidth_event()
            .expect("first completion scheduled");
        assert_eq!(first_finish, now + Duration::from_secs(1));

        let completions =
            state.recompute_bandwidth(first_finish, &mut egress_cap, &mut ingress_unlimited);
        assert_eq!(completions.len(), 1);
        assert!(completions[0].deliver);

        let completions = state.queue_transmission(
            now,
            origin.clone(),
            recipient.clone(),
            CHANNEL,
            make_bytes(2),
            Duration::ZERO,
            true,
            &mut egress_cap,
            &mut ingress_unlimited,
        );
        assert!(completions.is_empty());

        let completions =
            state.start_due_transmissions(now, &mut egress_cap, &mut ingress_unlimited);
        assert!(completions.is_empty());

        let completions =
            state.start_due_transmissions(first_finish, &mut egress_cap, &mut ingress_unlimited);
        assert!(completions.is_empty());

        let second_finish = state
            .next_bandwidth_event()
            .expect("second completion scheduled");
        assert_eq!(second_finish, first_finish + Duration::from_secs(1));

        let completions =
            state.recompute_bandwidth(second_finish, &mut egress_cap, &mut ingress_unlimited);
        assert_eq!(completions.len(), 1);
        assert!(completions[0].deliver);
        assert_eq!(completions[0].message.len(), 1_000);
        assert_eq!(completions[0].message[0], 2);
    }

    #[test]
    fn staggered_latencies_allow_overlap() {
        let mut state = TransmissionState::new();
        let start = SystemTime::UNIX_EPOCH;
        let origin = key(21);
        let recipient = key(22);

        let mut egress_cap = |_pk: &ed25519::PublicKey| Some(500_000u128); // 500 KB/s
        let mut ingress_unlimited = unlimited();

        let msg_a = Bytes::from(vec![0xAA; 1_000_000]);
        let msg_b = Bytes::from(vec![0xBB; 500_000]);

        let completions = state.queue_transmission(
            start,
            origin.clone(),
            recipient.clone(),
            CHANNEL,
            msg_a.clone(),
            Duration::from_millis(500),
            true,
            &mut egress_cap,
            &mut ingress_unlimited,
        );
        assert!(completions.is_empty());

        let completions = state.queue_transmission(
            start,
            origin.clone(),
            recipient.clone(),
            CHANNEL,
            msg_b.clone(),
            Duration::from_millis(100),
            true,
            &mut egress_cap,
            &mut ingress_unlimited,
        );
        assert!(completions.is_empty());

        let first_finish = state
            .next_bandwidth_event()
            .expect("message A completion scheduled");
        assert_eq!(first_finish, start + Duration::from_millis(2000));

        let completions =
            state.recompute_bandwidth(first_finish, &mut egress_cap, &mut ingress_unlimited);
        assert_eq!(completions.len(), 1);
        let completion_a = &completions[0];
        assert!(completion_a.deliver);
        assert_eq!(completion_a.message.len(), msg_a.len());
        assert_eq!(
            completion_a.arrival_complete_at,
            Some(first_finish + Duration::from_millis(500))
        );

        let next_ready = state
            .next_transmission_ready()
            .expect("message B send should be scheduled");
        assert_eq!(
            next_ready,
            first_finish + Duration::from_millis(500) - Duration::from_millis(100)
        );

        let completions =
            state.start_due_transmissions(next_ready, &mut egress_cap, &mut ingress_unlimited);
        assert!(completions.is_empty());

        let second_finish = state
            .next_bandwidth_event()
            .expect("message B completion scheduled");
        assert_eq!(second_finish, next_ready + Duration::from_secs_f64(1.0));

        let completions =
            state.recompute_bandwidth(second_finish, &mut egress_cap, &mut ingress_unlimited);
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
}
