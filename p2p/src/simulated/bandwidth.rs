use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime},
};

const NS_PER_SEC: u128 = 1_000_000_000;

#[derive(Clone, Debug)]
/// Portion of a transfer executed over a constant-rate window.
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
            .as_nanos() as u128
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
/// State for an in-flight transfer managed by the scheduler.
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
pub(super) struct FlowSnapshot {
    pub remaining: u128,
    pub ready_time: SystemTime,
}

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
                        .as_nanos() as u128;
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
struct Ratio {
    num: u128,
    den: u128,
}

impl Ratio {
    fn zero() -> Self {
        Self { num: 0, den: 1 }
    }

    fn from_int(value: u128) -> Self {
        Self { num: value, den: 1 }
    }

    fn is_zero(&self) -> bool {
        self.num == 0
    }

    fn cmp(&self, other: &Self) -> Ordering {
        (self.num * other.den).cmp(&(other.num * self.den))
    }

    fn add_assign(&mut self, other: &Self) {
        if other.is_zero() {
            return;
        }
        if self.is_zero() {
            self.num = other.num;
            self.den = other.den;
            return;
        }
        let lcm = lcm_u128(self.den, other.den);
        let lhs = self.num * (lcm / self.den);
        let rhs = other.num * (lcm / other.den);
        self.num = lhs + rhs;
        self.den = lcm;
        self.reduce();
    }

    fn sub_assign(&mut self, other: &Self) {
        if other.is_zero() {
            return;
        }
        if other.num == 0 {
            return;
        }
        let lcm = lcm_u128(self.den, other.den);
        let lhs = self.num * (lcm / self.den);
        let rhs = other.num * (lcm / other.den);
        self.num = lhs.saturating_sub(rhs);
        self.den = lcm;
        self.reduce();
    }

    fn mul_int(&self, value: u128) -> Self {
        if self.is_zero() || value == 0 {
            return Ratio::zero();
        }
        let gcd = gcd_u128(value, self.den);
        let num = self.num * (value / gcd);
        let den = self.den / gcd;
        let mut result = Ratio { num, den };
        result.reduce();
        result
    }

    fn div_int(&self, value: u128) -> Self {
        if self.is_zero() {
            return Ratio::zero();
        }
        let gcd = gcd_u128(self.num, value);
        let num = self.num / gcd;
        let den = self.den * (value / gcd);
        let mut result = Ratio { num, den };
        result.reduce();
        result
    }

    fn reduce(&mut self) {
        if self.num == 0 {
            self.den = 1;
            return;
        }
        let gcd = gcd_u128(self.num, self.den);
        self.num /= gcd;
        self.den /= gcd;
    }
}

#[derive(Clone, Debug)]
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
pub(super) struct FlowPlan<P> {
    pub origin: P,
    pub recipient: P,
    pub latency: Duration,
    pub deliver: bool,
    pub segments: Vec<Segment>,
}

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

struct ResourceState {
    capacity: Ratio,
}

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
            capacity: Ratio::from_int(value as u128),
        });
        index
    });
    indices.insert(key, idx);
    idx
}

fn ns_to_duration(ns: u128) -> Duration {
    if ns == 0 {
        return Duration::ZERO;
    }
    if ns > u128::from(u64::MAX) {
        Duration::from_secs(u64::MAX)
    } else {
        Duration::from_nanos(ns as u64)
    }
}

fn ceil_div_u128(num: u128, denom: u128) -> u128 {
    if denom == 0 {
        return u128::MAX;
    }
    if num == 0 {
        return 0;
    }
    (num + denom - 1) / denom
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let tmp = b;
        b = a % b;
        a = tmp;
    }
    a
}

fn lcm_u128(a: u128, b: u128) -> u128 {
    if a == 0 || b == 0 {
        return 0;
    }
    (a / gcd_u128(a, b)) * b
}

fn compute_rates<P: Clone + Ord>(
    active: &BTreeSet<usize>,
    flows: &[FlowState<P>],
    resources: &[ResourceState],
) -> Vec<Option<Ratio>> {
    let mut rates = vec![None; flows.len()];
    if active.is_empty() {
        return rates;
    }

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
            for idx in unfrozen.iter() {
                rates[*idx] = None;
            }
            break;
        }

        let delta = min_delta.unwrap();
        if delta.is_zero() {
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

    let mut flows: Vec<FlowState<P>> = Vec::new();
    flows.reserve(transfers.len());

    for transfer in transfers.iter() {
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
                    let ns = ceil_div_u128(numerator, rate.num);
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

        let event_time = match (next_finish, next_ready) {
            (Some(finish), Some(ready)) => finish.min(ready),
            (Some(finish), None) => finish,
            (None, Some(ready)) => ready,
            (None, None) => break,
        };

        let delta_ns = event_time
            .duration_since(time)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u128;

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
                .as_nanos() as u128;

            let mut bytes_in_interval = 0u128;

            for plan in plans.values() {
                for segment in &plan.segments {
                    if segment.end <= interval_start || segment.start >= interval_end {
                        continue;
                    }
                    let seg_start = segment.start.max(interval_start);
                    let seg_end = segment.end.min(interval_end);
                    let overlap_ns = seg_end.duration_since(seg_start).unwrap().as_nanos() as u128;
                    let total_ns = segment.duration_ns().max(1);
                    let contributed = segment.bytes * overlap_ns / total_ns;
                    bytes_in_interval += contributed;
                }
            }

            let rate = bytes_in_interval * NS_PER_SEC / interval_ns;
            assert!(rate <= 1500, "rate {} exceeds capacity", rate);
        }
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
