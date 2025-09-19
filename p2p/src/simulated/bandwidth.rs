//! Fair-queue bandwidth planner shared by the simulated network.
//!
//! The planner performs a single "water filling" step over the active flows to
//! compute per-flow transmission rates that respect both sender egress limits
//! and receiver ingress limits. The caller is responsible for advancing flow
//! progress according to the returned rates and re-running the planner whenever
//! the active set changes (for example when a message finishes or a new message
//! arrives).

use commonware_utils::math::u128::Ratio;
use std::{cmp::Ordering, collections::BTreeMap, time::Duration};

pub const NS_PER_SEC: u128 = 1_000_000_000;

#[derive(Clone, Debug)]
pub struct Flow<P> {
    pub id: u64,
    pub origin: P,
    pub recipient: P,
    pub requires_ingress: bool,
}

#[derive(Clone, Debug)]
pub enum FlowRate {
    Unlimited,
    Finite(Ratio),
}

impl FlowRate {}

impl PartialEq for FlowRate {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (FlowRate::Unlimited, FlowRate::Unlimited) => true,
            (FlowRate::Finite(left), FlowRate::Finite(right)) => {
                left.num == right.num && left.den == right.den
            }
            _ => false,
        }
    }
}

impl Eq for FlowRate {}

#[derive(Debug)]
struct Resource {
    capacity: Ratio,
    members: Vec<usize>,
}

impl Resource {
    fn new(limit: u128) -> Self {
        Self {
            capacity: Ratio::from_int(limit),
            members: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ResourceKey<P> {
    Egress(P),
    Ingress(P),
}

fn ensure_resource<P: Clone + Ord>(
    key: ResourceKey<P>,
    limit: Option<u128>,
    indices: &mut BTreeMap<ResourceKey<P>, usize>,
    resources: &mut Vec<Resource>,
) -> Option<usize> {
    if let Some(index) = indices.get(&key) {
        return Some(*index);
    }

    let idx = resources.len();
    resources.push(Resource::new(limit?));
    indices.insert(key, idx);
    Some(idx)
}

pub fn allocate<P, E, I>(
    flows: &[Flow<P>],
    mut egress_limit: E,
    mut ingress_limit: I,
) -> BTreeMap<u64, FlowRate>
where
    P: Clone + Ord,
    E: FnMut(&P) -> Option<u128>,
    I: FnMut(&P) -> Option<u128>,
{
    let mut result = BTreeMap::new();
    if flows.is_empty() {
        return result;
    }

    let mut indices: BTreeMap<ResourceKey<P>, usize> = BTreeMap::new();
    let mut resources: Vec<Resource> = Vec::new();
    let mut rates: Vec<Option<Ratio>> = vec![None; flows.len()];
    let mut active_indices: Vec<usize> = Vec::new();

    for (idx, flow) in flows.iter().enumerate() {
        let mut limited = false;

        if let Some(resource_idx) = ensure_resource(
            ResourceKey::Egress(flow.origin.clone()),
            egress_limit(&flow.origin),
            &mut indices,
            &mut resources,
        ) {
            resources[resource_idx].members.push(idx);
            limited = true;
        }

        if flow.requires_ingress {
            if let Some(resource_idx) = ensure_resource(
                ResourceKey::Ingress(flow.recipient.clone()),
                ingress_limit(&flow.recipient),
                &mut indices,
                &mut resources,
            ) {
                resources[resource_idx].members.push(idx);
                limited = true;
            }
        }

        if limited {
            rates[idx] = Some(Ratio::zero());
            active_indices.push(idx);
        }
    }

    compute_rates(&active_indices, &resources, &mut rates);

    for (idx, flow) in flows.iter().enumerate() {
        let rate = match &rates[idx] {
            None => FlowRate::Unlimited,
            Some(ratio) => FlowRate::Finite(ratio.clone()),
        };
        result.insert(flow.id, rate);
    }

    result
}

fn compute_rates(active: &[usize], resources: &[Resource], rates: &mut [Option<Ratio>]) {
    if active.is_empty() {
        return;
    }

    let mut remaining: Vec<Ratio> = resources.iter().map(|res| res.capacity.clone()).collect();

    let mut unfrozen = vec![false; rates.len()];
    for &idx in active {
        unfrozen[idx] = true;
    }
    let mut active_left = active.len();

    while active_left > 0 {
        let mut limiting = Vec::new();
        let mut min_delta: Option<Ratio> = None;

        for (res_idx, resource) in resources.iter().enumerate() {
            let users: u128 = resource
                .members
                .iter()
                .filter(|&&flow_idx| unfrozen[flow_idx])
                .count() as u128;
            if users == 0 {
                continue;
            }

            if remaining[res_idx].is_zero() {
                limiting.clear();
                limiting.push(res_idx);
                min_delta = Some(Ratio::zero());
                break;
            }

            let delta = remaining[res_idx].div_int(users);
            match &min_delta {
                None => {
                    min_delta = Some(delta);
                    limiting.clear();
                    limiting.push(res_idx);
                }
                Some(current) => match delta.cmp(current) {
                    Ordering::Less => {
                        min_delta = Some(delta);
                        limiting.clear();
                        limiting.push(res_idx);
                    }
                    Ordering::Equal => limiting.push(res_idx),
                    Ordering::Greater => {}
                },
            }
        }

        if min_delta.is_none() {
            for &idx in active {
                if unfrozen[idx] {
                    rates[idx] = None;
                }
            }
            break;
        }

        let delta = min_delta.unwrap();

        if delta.is_zero() {
            let mut newly_frozen = Vec::new();
            for &res_idx in &limiting {
                for &flow_idx in &resources[res_idx].members {
                    if unfrozen[flow_idx] {
                        newly_frozen.push(flow_idx);
                    }
                }
                remaining[res_idx] = Ratio::zero();
            }
            for idx in newly_frozen {
                if rates[idx].is_none() {
                    rates[idx] = Some(Ratio::zero());
                }
                if unfrozen[idx] {
                    unfrozen[idx] = false;
                    active_left -= 1;
                }
            }
            continue;
        }

        for &idx in active {
            if !unfrozen[idx] {
                continue;
            }
            match &mut rates[idx] {
                Some(rate) => rate.add_assign(&delta),
                None => {
                    let mut rate = Ratio::zero();
                    rate.add_assign(&delta);
                    rates[idx] = Some(rate);
                }
            }
        }

        let mut newly_frozen = Vec::new();
        for (res_idx, resource) in resources.iter().enumerate() {
            let users: u128 = resource
                .members
                .iter()
                .filter(|&&flow_idx| unfrozen[flow_idx])
                .count() as u128;
            if users == 0 {
                continue;
            }
            let usage = delta.mul_int(users);
            remaining[res_idx].sub_assign(&usage);
            if remaining[res_idx].is_zero() {
                for &flow_idx in &resource.members {
                    if unfrozen[flow_idx] {
                        newly_frozen.push(flow_idx);
                    }
                }
            }
        }

        for idx in newly_frozen {
            if unfrozen[idx] {
                unfrozen[idx] = false;
                active_left -= 1;
            }
        }
    }
}

pub fn time_to_deplete(rate: &FlowRate, bytes: u128) -> Option<Duration> {
    match rate {
        FlowRate::Unlimited => Some(Duration::ZERO),
        FlowRate::Finite(ratio) => {
            if ratio.is_zero() {
                if bytes == 0 {
                    Some(Duration::ZERO)
                } else {
                    None
                }
            } else {
                let numerator = bytes.saturating_mul(ratio.den).saturating_mul(NS_PER_SEC);
                let ns = div_ceil(numerator, ratio.num);
                Some(duration_from_ns(ns))
            }
        }
    }
}

pub fn transfer(rate: &FlowRate, elapsed: Duration, carry: &mut u128, remaining: u128) -> u128 {
    if remaining == 0 {
        return 0;
    }

    match rate {
        FlowRate::Unlimited => {
            *carry = 0;
            remaining
        }
        FlowRate::Finite(ratio) => {
            if ratio.is_zero() {
                return 0;
            }
            let delta_ns = elapsed.as_nanos();
            if delta_ns == 0 {
                return 0;
            }

            let denom = ratio.den.saturating_mul(NS_PER_SEC);
            if denom == 0 {
                *carry = 0;
                return remaining;
            }
            let numerator = ratio.num.saturating_mul(delta_ns);
            let total = numerator.saturating_add(*carry);
            let bytes = total / denom;
            *carry = total % denom;
            bytes.min(remaining)
        }
    }
}

fn div_ceil(num: u128, denom: u128) -> u128 {
    if denom == 0 {
        return u128::MAX;
    }
    let div = num / denom;
    if num % denom == 0 {
        div
    } else {
        div.saturating_add(1)
    }
}

fn duration_from_ns(ns: u128) -> Duration {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn constant(limit: u128) -> impl FnMut(&u8) -> Option<u128> {
        move |_| Some(limit)
    }

    fn unlimited() -> impl FnMut(&u8) -> Option<u128> {
        move |_| None
    }

    #[test]
    fn equal_share_on_single_egress() {
        let flows = vec![
            Flow {
                id: 1,
                origin: 1,
                recipient: 10,
                requires_ingress: true,
            },
            Flow {
                id: 2,
                origin: 1,
                recipient: 11,
                requires_ingress: true,
            },
        ];

        let allocations = allocate(&flows, constant(1_000), unlimited());
        assert_eq!(allocations.len(), 2);

        for rate in allocations.values() {
            let FlowRate::Finite(ratio) = rate else {
                panic!("expected finite rate");
            };
            assert_eq!(ratio.num, 500);
            assert_eq!(ratio.den, 1);
        }
    }

    #[test]
    fn ingress_limit_enforced() {
        let flows = vec![Flow {
            id: 1,
            origin: 1,
            recipient: 5,
            requires_ingress: true,
        }];

        let allocations = allocate(&flows, unlimited(), constant(2_000));
        let rate = allocations.get(&1).expect("missing flow");
        let FlowRate::Finite(ratio) = rate else {
            panic!("expected finite rate");
        };
        assert_eq!(ratio.num, 2_000);
        assert_eq!(ratio.den, 1);
    }

    #[test]
    fn unlimited_flow_finishes_immediately() {
        let flows = vec![Flow {
            id: 7,
            origin: 1,
            recipient: 2,
            requires_ingress: false,
        }];

        let allocations = allocate(&flows, unlimited(), unlimited());
        assert_eq!(allocations[&7], FlowRate::Unlimited);
    }

    #[test]
    fn transfer_accumulates_carry() {
        let ratio = Ratio { num: 1, den: 2 }; // 0.5 bytes per second
        let mut carry = 0;
        let rate = FlowRate::Finite(ratio);
        let first = transfer(&rate, Duration::from_millis(500), &mut carry, 10);
        assert_eq!(first, 0); // 0.25 bytes rounded down
        assert_ne!(carry, 0);
        let second = transfer(&rate, Duration::from_millis(1500), &mut carry, 10);
        // 0.75 + previous 0.25 == 1 byte
        assert_eq!(first + second, 1);
    }

    #[test]
    fn completion_time_calculation() {
        let ratio = Ratio::from_int(500);
        let rate = FlowRate::Finite(ratio);
        let time = time_to_deplete(&rate, 1_000).expect("finite time");
        assert_eq!(time.as_secs(), 2);
    }
}
