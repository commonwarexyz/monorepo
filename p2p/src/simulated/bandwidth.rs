//! Progressive-filling bandwidth planner shared by the simulated network.
//!
//! The planner consumes a snapshot of all in-flight transfers and emits
//! piecewise-constant schedules that respect both the sender's egress limit and
//! the receiver's ingress limit. Rates are computed with a water-filling
//! algorithm using exact rational arithmetic so the resulting plan is
//! deterministic and work-conserving.

use commonware_utils::Ratio;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime},
};

const NS_PER_SEC: u128 = 1_000_000_000;

#[derive(Clone, Debug)]
/// Portion of a transfer executed at a constant rate within the generated schedule.
pub(super) struct Segment {
    start: SystemTime,
    end: SystemTime,
    bytes: u128,
}

impl Segment {
    fn duration_ns(&self) -> u128 {
        self.end
            .duration_since(self.start)
            .unwrap_or(Duration::ZERO)
            .as_nanos()
    }

    pub(super) fn start_time(&self) -> SystemTime {
        self.start
    }

    pub(super) fn shifted(&self, delta: Duration) -> Segment {
        Segment {
            start: self
                .start
                .checked_add(delta)
                .expect("shift would overflow start time"),
            end: self
                .end
                .checked_add(delta)
                .expect("shift would overflow end time"),
            bytes: self.bytes,
        }
    }
}

#[derive(Debug)]
/// Private state recorded for each flow inside a peer-local schedule.
struct Flow {
    bytes_total: u128,
    bytes_delivered: u128,
    ready_time: SystemTime,
    segments: Vec<Segment>,
}

impl Flow {
    fn new(bytes: usize, ready_time: SystemTime) -> Self {
        Self {
            bytes_total: bytes as u128,
            bytes_delivered: 0,
            ready_time,
            segments: Vec::new(),
        }
    }

    fn remaining(&self) -> u128 {
        self.bytes_total.saturating_sub(self.bytes_delivered)
    }

    fn completion_time(&self) -> Option<SystemTime> {
        if let Some(last) = self.segments.last() {
            Some(last.end)
        } else if self.remaining() == 0 {
            Some(self.ready_time)
        } else {
            None
        }
    }

    fn reset_segments(&mut self, segments: Vec<Segment>, default_start: SystemTime) {
        self.segments = segments;
        self.ready_time = self
            .segments
            .first()
            .map(|s| s.start)
            .unwrap_or(default_start);
    }

    fn snapshot(&self) -> FlowSnapshot {
        FlowSnapshot {
            remaining: self.remaining(),
            ready_time: self.ready_time,
        }
    }
}

#[derive(Clone, Debug)]
/// Snapshot of flow progress exposed to the planner.
pub(super) struct FlowSnapshot {
    pub remaining: u128,
    pub ready_time: SystemTime,
}

/// Per-peer view of the active flows and their assigned segments.
pub(super) struct Schedule {
    pub(super) bps: usize,
    flows: BTreeMap<u64, Flow>,
}

impl Schedule {
    pub(super) fn new(bps: usize) -> Self {
        Self {
            bps,
            flows: BTreeMap::new(),
        }
    }

    pub(super) fn add_flow(&mut self, flow_id: u64, start: SystemTime, bytes: usize) {
        let flow = Flow::new(bytes, start);
        let replaced = self.flows.insert(flow_id, flow);
        debug_assert!(replaced.is_none(), "flow id reused");
    }

    /// Discard segments that end before `now`, crediting their bytes to the flow and
    /// trimming partially-completed segments.
    pub(super) fn prune(&mut self, now: SystemTime) {
        let mut completed = Vec::new();
        for (&id, flow) in self.flows.iter_mut() {
            let mut updated = Vec::new();
            for mut segment in flow.segments.drain(..) {
                if segment.end <= now {
                    flow.bytes_delivered = flow.bytes_delivered.saturating_add(segment.bytes);
                } else if segment.start < now {
                    let total_ns = segment.duration_ns().max(1);
                    let elapsed_ns = now
                        .duration_since(segment.start)
                        .unwrap_or(Duration::ZERO)
                        .as_nanos();
                    let credited = segment.bytes * elapsed_ns / total_ns;
                    let credited = credited.min(segment.bytes);
                    flow.bytes_delivered = flow.bytes_delivered.saturating_add(credited);
                    let remaining_bytes = segment.bytes.saturating_sub(credited);
                    if remaining_bytes > 0 {
                        segment.start = now;
                        segment.bytes = remaining_bytes;
                        updated.push(segment);
                    }
                } else {
                    updated.push(segment);
                }
            }

            flow.segments = updated;
            flow.ready_time = flow.segments.first().map(|s| s.start).unwrap_or(now);

            if flow.remaining() == 0 {
                completed.push(id);
            }
        }

        for id in completed {
            self.flows.remove(&id);
        }
    }

    pub(super) fn reset_flow_segments(
        &mut self,
        flow_id: u64,
        segments: Vec<Segment>,
        default_start: SystemTime,
    ) {
        if let Some(flow) = self.flows.get_mut(&flow_id) {
            flow.reset_segments(segments, default_start);
        }
    }

    pub(super) fn completion_time(&self, flow_id: u64) -> Option<SystemTime> {
        self.flows
            .get(&flow_id)
            .and_then(|flow| flow.completion_time())
    }

    pub(super) fn flow_segments(&self, flow_id: u64) -> Option<&[Segment]> {
        self.flows.get(&flow_id).map(|f| f.segments.as_slice())
    }

    pub(super) fn flow_snapshot(&self, flow_id: u64) -> Option<FlowSnapshot> {
        self.flows.get(&flow_id).map(|flow| flow.snapshot())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ResourceKey<P> {
    Egress(P),
    Ingress(P),
}

#[derive(Clone, Debug)]
/// Transfer snapshot supplied to the planner. `ready_time` denotes the first
/// instant at which the sender can resume transmitting bytes.
pub(super) struct Transfer<P> {
    pub id: u64,
    pub origin: P,
    pub recipient: P,
    pub remaining: u128,
    pub ready_time: SystemTime,
    pub latency: Duration,
    pub deliver: bool,
}

#[derive(Clone, Debug)]
/// Planner output for a single flow (before latency is applied to the receiver).
pub(super) struct FlowPlan<P> {
    pub origin: P,
    pub recipient: P,
    pub latency: Duration,
    pub deliver: bool,
    pub segments: Vec<Segment>,
}

/// Planner-internal representation of a transfer while rates are being derived.
struct FlowState<P> {
    id: u64,
    origin: P,
    recipient: P,
    latency: Duration,
    deliver: bool,
    ready_time: SystemTime,
    remaining: u128,
    sender_resource: Option<usize>,
    receiver_resource: Option<usize>,
    segments: Vec<Segment>,
}

/// Remaining capacity tracker for one logical resource (sender egress or receiver ingress).
struct ResourceState {
    capacity: Ratio,
}

/// Lazily allocate a resource slot. If `limit` is `None` the resource is treated as unbounded.
fn ensure_resource<P: Clone + Ord>(
    key: ResourceKey<P>,
    limit: Option<u128>,
    indices: &mut BTreeMap<ResourceKey<P>, Option<usize>>,
    resources: &mut Vec<ResourceState>,
) -> Option<usize> {
    if let Some(idx) = indices.get(&key) {
        return *idx;
    }
    let idx = limit.map(|value| {
        let index = resources.len();
        resources.push(ResourceState {
            capacity: Ratio::from_int(value),
        });
        index
    });
    indices.insert(key, idx);
    idx
}

/// Convert an abstract nanosecond interval into a concrete `Duration`.
///
/// The planner works in `u128` nanoseconds so it can represent very long
/// intervals without overflow. `std::time::Duration`, however, is capped at
/// `u64::MAX` seconds with nanosecond precision. We therefore clamp extremely
/// large values to that maximum and otherwise split the `u128` into whole seconds
/// and the remaining nanoseconds.
fn ns_to_duration(ns: u128) -> Duration {
    if ns == 0 {
        return Duration::ZERO;
    }
    let max_ns = u128::from(u64::MAX) * NS_PER_SEC;
    if ns >= max_ns {
        return Duration::from_secs(u64::MAX);
    }
    let secs = (ns / NS_PER_SEC) as u64;
    let nanos = (ns % NS_PER_SEC) as u32;
    Duration::new(secs, nanos)
}

fn div_ceil_or_max(num: u128, denom: u128) -> u128 {
    // `denom` reflects the instantaneous rate allocated to a flow. If contention
    // evaporates we treat the horizon as effectively infinite so callers can
    // clamp the finishing time to their own limits; returning `u128::MAX` lets
    // the planner detect that scenario without introducing special cases.
    if denom == 0 {
        return u128::MAX;
    }
    num.div_ceil(denom)
}

/// Core progressive-filling loop. Returns the instantaneous rate (bytes/sec) for
/// each active flow expressed as a `Ratio<num, den>` where `num / den == Bps`.
fn compute_rates<P: Clone + Ord>(
    active: &BTreeSet<usize>,
    flows: &[FlowState<P>],
    resources: &[ResourceState],
) -> Vec<Option<Ratio>> {
    let mut rates = vec![None; flows.len()];
    if active.is_empty() {
        return rates;
    }

    // Map each resource to the flow indices that currently depend on it.
    let mut resource_sets: Vec<BTreeSet<usize>> =
        resources.iter().map(|_| BTreeSet::new()).collect();

    for &idx in active {
        if let Some(res) = flows[idx].sender_resource {
            resource_sets[res].insert(idx);
        }
        if let Some(res) = flows[idx].receiver_resource {
            resource_sets[res].insert(idx);
        }
    }

    let mut remaining: Vec<Ratio> = resources.iter().map(|r| r.capacity.clone()).collect();
    let mut unfrozen = active.clone();

    loop {
        if unfrozen.is_empty() {
            break;
        }

        let mut limiting: Vec<usize> = Vec::new();
        let mut min_delta: Option<Ratio> = None;

        for (idx, set) in resource_sets.iter().enumerate() {
            if set.is_empty() {
                continue;
            }
            let users: u128 = set.intersection(&unfrozen).count() as u128;
            if users == 0 {
                continue;
            }
            if remaining[idx].is_zero() {
                limiting.push(idx);
                min_delta = Some(Ratio::zero());
                continue;
            }
            let delta = remaining[idx].div_int(users);
            match &min_delta {
                None => {
                    min_delta = Some(delta);
                    limiting.clear();
                    limiting.push(idx);
                }
                Some(current) => match delta.cmp(current) {
                    Ordering::Less => {
                        min_delta = Some(delta);
                        limiting.clear();
                        limiting.push(idx);
                    }
                    Ordering::Equal => limiting.push(idx),
                    Ordering::Greater => {}
                },
            }
        }

        if min_delta.is_none() {
            // No resource constrains the remaining flows (everything is unlimited).
            for idx in unfrozen.iter() {
                rates[*idx] = None;
            }
            break;
        }

        let delta = min_delta.unwrap();
        if delta.is_zero() {
            // One or more resources are already exhausted; freeze the flows that
            // depend on them and continue with the rest.
            let mut saturated = Vec::new();
            for &idx in &limiting {
                for flow_idx in resource_sets[idx].intersection(&unfrozen) {
                    saturated.push(*flow_idx);
                }
                remaining[idx] = Ratio::zero();
            }
            for idx in saturated {
                unfrozen.remove(&idx);
                if rates[idx].is_none() {
                    rates[idx] = Some(Ratio::zero());
                }
            }
            continue;
        }

        for idx in unfrozen.iter() {
            match &mut rates[*idx] {
                Some(rate) => rate.add_assign(&delta),
                None => {
                    let mut rate = Ratio::zero();
                    rate.add_assign(&delta);
                    rates[*idx] = Some(rate);
                }
            }
        }

        let mut saturated = Vec::new();
        for (res_idx, set) in resource_sets.iter().enumerate() {
            let users = set.intersection(&unfrozen).count() as u128;
            if users == 0 {
                continue;
            }
            let usage = delta.mul_int(users);
            // Deduct the portion of the resource consumed over this time slice.
            remaining[res_idx].sub_assign(&usage);
            if remaining[res_idx].is_zero() {
                for flow_idx in set.intersection(&unfrozen) {
                    saturated.push(*flow_idx);
                }
            }
        }

        for idx in saturated {
            unfrozen.remove(&idx);
        }
    }

    rates
}

/// Produce bandwidth plans for every active transfer at `now`.
///
/// The closures expose per-peer limits. Returning `None` signals "unlimited" for that side.
/// The resulting `FlowPlan` objects contain sender-oriented segments; callers can shift them
/// by latency for ingress scheduling.
pub(super) fn plan_transmissions<P, E, I>(
    now: SystemTime,
    transfers: &[Transfer<P>],
    mut egress_limit: E,
    mut ingress_limit: I,
) -> BTreeMap<u64, FlowPlan<P>>
where
    P: Clone + Ord,
    E: FnMut(&P) -> Option<u128>,
    I: FnMut(&P) -> Option<u128>,
{
    if transfers.is_empty() {
        return BTreeMap::new();
    }

    let mut resource_indices: BTreeMap<ResourceKey<P>, Option<usize>> = BTreeMap::new();
    let mut resources: Vec<ResourceState> = Vec::new();

    let mut flows: Vec<FlowState<P>> = Vec::with_capacity(transfers.len());
    for transfer in transfers.iter() {
        // Egress is always considered; ingress only matters when the transfer
        // should be delivered (i.e. not dropped due to link failure).
        let sender_limit = egress_limit(&transfer.origin);
        let sender_idx = ensure_resource(
            ResourceKey::Egress(transfer.origin.clone()),
            sender_limit,
            &mut resource_indices,
            &mut resources,
        );

        let receiver_idx = if transfer.deliver {
            let limit = ingress_limit(&transfer.recipient);
            ensure_resource(
                ResourceKey::Ingress(transfer.recipient.clone()),
                limit,
                &mut resource_indices,
                &mut resources,
            )
        } else {
            None
        };

        flows.push(FlowState {
            id: transfer.id,
            origin: transfer.origin.clone(),
            recipient: transfer.recipient.clone(),
            latency: transfer.latency,
            deliver: transfer.deliver,
            ready_time: transfer.ready_time,
            remaining: transfer.remaining,
            sender_resource: sender_idx,
            receiver_resource: receiver_idx,
            segments: Vec::new(),
        });
    }

    let mut time = now;

    loop {
        let active: BTreeSet<usize> = flows
            .iter()
            .enumerate()
            .filter(|(_, flow)| flow.remaining > 0 && flow.ready_time <= time)
            .map(|(idx, _)| idx)
            .collect();

        if active.is_empty() {
            if let Some(next_ready) = flows
                .iter()
                .filter(|flow| flow.remaining > 0)
                .map(|flow| flow.ready_time)
                .filter(|t| *t > time)
                .min()
            {
                time = next_ready;
                continue;
            }
            break;
        }

        // At this point at least one flow is active; derive its instantaneous rate.
        let rates = compute_rates(&active, &flows, &resources);

        let mut next_finish: Option<SystemTime> = None;
        let mut finish_ns: Vec<Option<u128>> = vec![None; flows.len()];

        for &idx in active.iter() {
            match &rates[idx] {
                None => {
                    finish_ns[idx] = Some(0);
                    next_finish = Some(time);
                }
                Some(rate) if rate.is_zero() => {}
                Some(rate) => {
                    let remaining = flows[idx].remaining;
                    if remaining == 0 {
                        finish_ns[idx] = Some(0);
                        next_finish = Some(time);
                        continue;
                    }
                    let numerator = remaining
                        .saturating_mul(rate.den)
                        .saturating_mul(NS_PER_SEC);
                    let ns = div_ceil_or_max(numerator, rate.num);
                    finish_ns[idx] = Some(ns);
                    let finish_time = time
                        .checked_add(ns_to_duration(ns))
                        .expect("finish time overflow");
                    next_finish = match next_finish {
                        None => Some(finish_time),
                        Some(current) => Some(current.min(finish_time)),
                    };
                }
            }
        }

        let next_ready = flows
            .iter()
            .filter(|flow| flow.remaining > 0 && flow.ready_time > time)
            .map(|flow| flow.ready_time)
            .min();

        // Jump to the next "interesting" instant: either the earliest completion or
        // the arrival of a new flow.
        let event_time = match (next_finish, next_ready) {
            (Some(finish), Some(ready)) => finish.min(ready),
            (Some(finish), None) => finish,
            (None, Some(ready)) => ready,
            (None, None) => break,
        };

        let delta_ns = event_time
            .duration_since(time)
            .unwrap_or(Duration::ZERO)
            .as_nanos();

        for &idx in active.iter() {
            let flow = &mut flows[idx];
            let rate = &rates[idx];
            let mut bytes = 0u128;
            let finishing = match finish_ns[idx] {
                Some(ns) => {
                    let finish_time = time
                        .checked_add(ns_to_duration(ns))
                        .expect("finish time overflow");
                    finish_time <= event_time
                }
                None => false,
            };

            match rate {
                None => {
                    bytes = flow.remaining;
                }
                Some(r) if r.is_zero() => {}
                Some(r) => {
                    // Convert the fractional rate back into bytes over the current interval.
                    if delta_ns == 0 {
                        if finishing {
                            bytes = flow.remaining;
                        }
                    } else {
                        let numerator = r.num.saturating_mul(delta_ns);
                        let denominator = r.den.saturating_mul(NS_PER_SEC);
                        if denominator > 0 {
                            bytes = numerator / denominator;
                        }
                        if finishing {
                            bytes = flow.remaining;
                        } else {
                            bytes = bytes.min(flow.remaining);
                        }
                    }
                }
            }

            if bytes > 0 {
                let segment = Segment {
                    start: time,
                    end: event_time,
                    bytes,
                };
                flow.segments.push(segment);
                flow.remaining = flow.remaining.saturating_sub(bytes);
            }

            flow.ready_time = event_time;
        }

        time = event_time;

        if flows.iter().all(|flow| flow.remaining == 0) {
            break;
        }
    }

    // Return the sender-oriented plans keyed by flow id for deterministic lookup.
    flows
        .into_iter()
        .map(|flow| {
            let plan = FlowPlan {
                origin: flow.origin.clone(),
                recipient: flow.recipient.clone(),
                latency: flow.latency,
                deliver: flow.deliver,
                segments: flow.segments,
            };
            (flow.id, plan)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn capacity_map(value: u128) -> impl FnMut(&u8) -> Option<u128> {
        move |_| Some(value)
    }

    #[test]
    fn test_progressive_share_two_transfers() {
        let now = UNIX_EPOCH;
        let transfers = vec![
            Transfer {
                id: 1,
                origin: 1,
                recipient: 2,
                remaining: 2000,
                ready_time: now,
                latency: Duration::ZERO,
                deliver: true,
            },
            Transfer {
                id: 2,
                origin: 1,
                recipient: 2,
                remaining: 1000,
                ready_time: now + Duration::from_secs(1),
                latency: Duration::ZERO,
                deliver: true,
            },
        ];

        let plans = plan_transmissions(now, &transfers, capacity_map(1000), capacity_map(1000));

        let seg1 = plans.get(&1).unwrap();
        let seg2 = plans.get(&2).unwrap();

        assert_eq!(seg1.segments.len(), 2);
        assert_eq!(seg2.segments.len(), 1);

        assert_eq!(seg1.segments[0].start, now);
        assert_eq!(seg1.segments[0].end, now + Duration::from_secs(1));
        assert_eq!(seg1.segments[0].bytes, 1000);

        assert_eq!(seg1.segments[1].start, now + Duration::from_secs(1));
        assert_eq!(seg1.segments[1].end, now + Duration::from_secs(3));
        assert_eq!(seg1.segments[1].bytes, 1000);

        assert_eq!(seg2.segments[0].start, now + Duration::from_secs(1));
        assert_eq!(seg2.segments[0].end, now + Duration::from_secs(3));
        assert_eq!(seg2.segments[0].bytes, 1000);
    }

    #[test]
    fn test_progressive_share_three_transfers() {
        let now = UNIX_EPOCH;
        let transfers = vec![
            Transfer {
                id: 1,
                origin: 1,
                recipient: 2,
                remaining: 1200,
                ready_time: now,
                latency: Duration::ZERO,
                deliver: true,
            },
            Transfer {
                id: 2,
                origin: 1,
                recipient: 2,
                remaining: 600,
                ready_time: now + Duration::from_millis(200),
                latency: Duration::ZERO,
                deliver: true,
            },
            Transfer {
                id: 3,
                origin: 3,
                recipient: 2,
                remaining: 600,
                ready_time: now + Duration::from_millis(200),
                latency: Duration::ZERO,
                deliver: true,
            },
        ];

        let egress_cap = |pk: &u8| match pk {
            1 => Some(1200),
            3 => Some(600),
            _ => Some(u128::MAX),
        };

        let ingress_cap = |_: &u8| Some(1200);

        let plans = plan_transmissions(now, &transfers, egress_cap, ingress_cap);

        let seg1 = plans.get(&1).unwrap();
        let seg2 = plans.get(&2).unwrap();
        let seg3 = plans.get(&3).unwrap();

        assert_eq!(seg1.segments.len(), 3);
        assert_eq!(seg2.segments.len(), 1);
        assert_eq!(seg3.segments.len(), 1);

        assert_eq!(seg1.segments[0].start, now);
        assert_eq!(seg1.segments[0].end, now + Duration::from_millis(200));
        assert_eq!(seg1.segments[0].bytes, 240);

        assert_eq!(seg1.segments[1].start, now + Duration::from_millis(200));
        assert_eq!(seg1.segments[1].end, now + Duration::from_millis(1700));
        assert_eq!(seg1.segments[1].bytes, 600);

        assert_eq!(seg1.segments[2].start, now + Duration::from_millis(1700));
        assert_eq!(seg1.segments[2].end, now + Duration::from_secs(2));
        assert_eq!(seg1.segments[2].bytes, 360);

        assert_eq!(seg2.segments[0].start, now + Duration::from_millis(200));
        assert_eq!(seg2.segments[0].end, now + Duration::from_millis(1700));
        assert_eq!(seg2.segments[0].bytes, 600);

        assert_eq!(seg3.segments[0].start, seg2.segments[0].start);
        assert_eq!(seg3.segments[0].end, seg2.segments[0].end);
        assert_eq!(seg3.segments[0].bytes, 600);
    }

    #[test]
    fn test_unlimited_capacity() {
        let now = UNIX_EPOCH;
        let transfers = vec![Transfer {
            id: 1,
            origin: 1,
            recipient: 2,
            remaining: 1024,
            ready_time: now,
            latency: Duration::ZERO,
            deliver: true,
        }];

        let plans = plan_transmissions(now, &transfers, |_pk| None, |_pk| None);

        let seg = plans.get(&1).unwrap();
        assert_eq!(seg.segments.len(), 1);
        assert_eq!(seg.segments[0].start, now);
        assert_eq!(seg.segments[0].end, now);
        assert_eq!(seg.segments[0].bytes, 1024);
    }

    #[test]
    fn test_capacity_respected() {
        let now = UNIX_EPOCH;
        let transfers = vec![
            Transfer {
                id: 1,
                origin: 1,
                recipient: 4,
                remaining: 1500,
                ready_time: now,
                latency: Duration::ZERO,
                deliver: true,
            },
            Transfer {
                id: 2,
                origin: 2,
                recipient: 4,
                remaining: 1500,
                ready_time: now,
                latency: Duration::ZERO,
                deliver: true,
            },
            Transfer {
                id: 3,
                origin: 3,
                recipient: 4,
                remaining: 1500,
                ready_time: now,
                latency: Duration::ZERO,
                deliver: true,
            },
        ];

        let egress = |_pk: &u8| Some(1500);
        let ingress = |_pk: &u8| Some(1500);

        let plans = plan_transmissions(now, &transfers, egress, ingress);

        let mut boundaries = Vec::new();
        for plan in plans.values() {
            for segment in &plan.segments {
                boundaries.push(segment.start);
                boundaries.push(segment.end);
            }
        }

        boundaries.sort();
        boundaries.dedup();

        for pair in boundaries.windows(2) {
            let interval_start = pair[0];
            let interval_end = pair[1];
            if interval_end <= interval_start {
                continue;
            }

            let interval_ns = interval_end
                .duration_since(interval_start)
                .unwrap()
                .as_nanos();

            let mut bytes_in_interval = 0u128;

            for plan in plans.values() {
                for segment in &plan.segments {
                    if segment.end <= interval_start || segment.start >= interval_end {
                        continue;
                    }
                    let seg_start = segment.start.max(interval_start);
                    let seg_end = segment.end.min(interval_end);
                    let overlap_ns = seg_end.duration_since(seg_start).unwrap().as_nanos();
                    let total_ns = segment.duration_ns().max(1);
                    let contributed = segment.bytes * overlap_ns / total_ns;
                    bytes_in_interval += contributed;
                }
            }

            let rate = bytes_in_interval * NS_PER_SEC / interval_ns;
            assert!(rate <= 1500, "rate {rate} exceeds capacity");
        }
    }

    #[test]
    fn test_receiver_bottleneck_shared_across_origins() {
        let now = UNIX_EPOCH;
        let transfers = vec![
            Transfer {
                id: 1,
                origin: 1u8,
                recipient: 10,
                remaining: 1000,
                ready_time: now,
                latency: Duration::ZERO,
                deliver: true,
            },
            Transfer {
                id: 2,
                origin: 2u8,
                recipient: 10,
                remaining: 1000,
                ready_time: now,
                latency: Duration::ZERO,
                deliver: true,
            },
        ];

        let mut plans = plan_transmissions(
            now,
            &transfers,
            |_origin| Some(2000),
            |_recipient| Some(1000),
        );

        for id in [1u64, 2] {
            let plan = plans.remove(&id).unwrap();
            assert_eq!(plan.segments.len(), 1);
            let segment = &plan.segments[0];
            assert_eq!(segment.start, now);
            assert_eq!(segment.end, now + Duration::from_secs(2));
            assert_eq!(segment.bytes, 1000);
        }
    }

    #[test]
    fn test_sender_bottleneck_limits_all_outgoing_flows() {
        let now = UNIX_EPOCH;
        let transfers = vec![
            Transfer {
                id: 1,
                origin: 1u8,
                recipient: 10,
                remaining: 1000,
                ready_time: now,
                latency: Duration::ZERO,
                deliver: true,
            },
            Transfer {
                id: 2,
                origin: 1u8,
                recipient: 11,
                remaining: 1000,
                ready_time: now,
                latency: Duration::ZERO,
                deliver: true,
            },
        ];

        let plans = plan_transmissions(
            now,
            &transfers,
            |_origin| Some(1000),
            |_recipient| Some(10_000),
        );

        let seg1 = plans.get(&1).unwrap();
        let seg2 = plans.get(&2).unwrap();

        assert_eq!(seg1.segments.len(), 1);
        assert_eq!(seg2.segments.len(), 1);
        assert_eq!(seg1.segments[0].start, now);
        assert_eq!(seg2.segments[0].start, now);
        assert_eq!(seg1.segments[0].end, now + Duration::from_secs(2));
        assert_eq!(seg2.segments[0].end, now + Duration::from_secs(2));
        assert_eq!(seg1.segments[0].bytes, 1000);
        assert_eq!(seg2.segments[0].bytes, 1000);
    }

    #[test]
    fn test_zero_capacity_produces_no_segments() {
        let now = UNIX_EPOCH;
        let transfers = vec![Transfer {
            id: 1,
            origin: 1u8,
            recipient: 2,
            remaining: 1024,
            ready_time: now,
            latency: Duration::ZERO,
            deliver: true,
        }];

        let plans = plan_transmissions(now, &transfers, |_origin| Some(0), |_recipient| Some(1024));

        let seg = plans.get(&1).unwrap();
        assert!(seg.segments.is_empty());
    }

    #[test]
    fn test_future_ready_time_deferred_start() {
        let now = UNIX_EPOCH;
        let transfers = vec![
            Transfer {
                id: 1,
                origin: 1u8,
                recipient: 2,
                remaining: 1000,
                ready_time: now,
                latency: Duration::ZERO,
                deliver: true,
            },
            Transfer {
                id: 2,
                origin: 1u8,
                recipient: 3,
                remaining: 1000,
                ready_time: now + Duration::from_secs(1),
                latency: Duration::ZERO,
                deliver: true,
            },
        ];

        let plans = plan_transmissions(
            now,
            &transfers,
            |_origin| Some(1000),
            |_recipient| Some(1000),
        );

        let seg1 = plans.get(&1).unwrap();
        let seg2 = plans.get(&2).unwrap();

        assert_eq!(seg1.segments.len(), 1);
        assert_eq!(seg1.segments[0].start, now);
        assert_eq!(seg1.segments[0].end, now + Duration::from_secs(1));

        assert_eq!(seg2.segments.len(), 1);
        assert_eq!(seg2.segments[0].start, now + Duration::from_secs(1));
        assert_eq!(seg2.segments[0].end, now + Duration::from_secs(2));
    }

    #[test]
    fn test_prune_drops_completed_flows() {
        let now = UNIX_EPOCH;
        let mut schedule = Schedule::new(1000);

        schedule.add_flow(1, now, 1000);

        let transfers = vec![Transfer {
            id: 1,
            origin: 1,
            recipient: 2,
            remaining: 1000,
            ready_time: now,
            latency: Duration::ZERO,
            deliver: false,
        }];

        let plans = plan_transmissions(now, &transfers, |_pk| Some(1000), |_pk| None);

        let segments = plans.get(&1).unwrap().segments.clone();
        schedule.reset_flow_segments(1, segments, now);

        let completion = schedule.completion_time(1).unwrap();
        assert_eq!(completion, now + Duration::from_secs(1));

        schedule.prune(now + Duration::from_secs(2));
        assert!(schedule.flow_segments(1).is_none());
    }
}
