//! Max-min fair (via progressive filling) bandwidth planner.
//!
//! The planner performs progressive filling over the active flows to
//! compute per-flow transmission rates that respect both sender egress limits
//! and receiver ingress limits (to ensure max-min fairness). The caller is responsible
//! for advancing flow progress according to the returned rates and invoking the planner
//! whenever the active set changes (for example when a message finishes or a new message
//! arrives).

use commonware_utils::Ratio;
use std::{cmp::Ordering, collections::BTreeMap, time::Duration};

/// Number of nanoseconds in a second.
pub const NS_PER_SEC: u128 = 1_000_000_000;

/// Minimal description of a simulated transmission path.
#[derive(Clone, Debug)]
pub struct Flow<P> {
    pub id: u64,
    pub origin: P,
    pub recipient: P,
    pub requires_ingress: bool,
}

/// Resulting per-flow throughput expressed as bytes/second.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rate {
    Unlimited,
    Finite(Ratio),
}

/// Shared capacity constraint (either egress or ingress) tracked by the planner.
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

/// Identifier used to deduplicate resource entries across flows.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ResourceKey<P> {
    Egress(P),
    Ingress(P),
}

/// Ensures an entry exists for the given resource, returning its index if limited.
fn insert<P: Clone + Ord>(
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

/// Computes a fair allocation for the provided `flows`, returning per-flow rates.
///
/// Each sender/receiver cap is modeled as a shared resource. Every flow registers
/// with the resources it touches, after which we perform progressive filling: raise
/// the rate of all unfrozen flows uniformly until a resource is depleted, freeze flows
/// using that resource, and repeat. This yields a deterministic, starvation-free assignment
/// that honors both ingress and egress limits.
pub fn allocate<P, E, I>(
    flows: &[Flow<P>],
    mut egress_limit: E,
    mut ingress_limit: I,
) -> BTreeMap<u64, Rate>
where
    P: Clone + Ord,
    E: FnMut(&P) -> Option<u128>,
    I: FnMut(&P) -> Option<u128>,
{
    // If there are no flows, there is nothing to allocate.
    let mut result = BTreeMap::new();
    if flows.is_empty() {
        return result;
    }

    // Register all flows with the resources they touch.
    let mut indices: BTreeMap<ResourceKey<P>, usize> = BTreeMap::new();
    let mut resources: Vec<Resource> = Vec::new();
    let mut rates: Vec<Option<Ratio>> = vec![None; flows.len()];
    let mut active_indices: Vec<usize> = Vec::new();
    for (idx, flow) in flows.iter().enumerate() {
        // Always insert the egress resource.
        let mut limited = false;
        if let Some(resource_idx) = insert(
            ResourceKey::Egress(flow.origin.clone()),
            egress_limit(&flow.origin),
            &mut indices,
            &mut resources,
        ) {
            resources[resource_idx].members.push(idx);
            limited = true;
        }

        // If the flow requires ingress, insert the ingress resource (may be a no-op
        // if the message will be dropped).
        if flow.requires_ingress {
            if let Some(resource_idx) = insert(
                ResourceKey::Ingress(flow.recipient.clone()),
                ingress_limit(&flow.recipient),
                &mut indices,
                &mut resources,
            ) {
                resources[resource_idx].members.push(idx);
                limited = true;
            }
        }

        // If the flow is limited by a resource, set its rate to zero (we'll increase it later).
        if limited {
            rates[idx] = Some(Ratio::zero());
            active_indices.push(idx);
        }
    }

    // Compute the rates for the constrained flows.
    compute_rates(&active_indices, &resources, &mut rates);

    // Convert the rates to the result format.
    for (idx, flow) in flows.iter().enumerate() {
        let rate = match &rates[idx] {
            None => Rate::Unlimited,
            Some(ratio) => Rate::Finite(ratio.clone()),
        };
        result.insert(flow.id, rate);
    }

    result
}

/// Distribute capacity among the constrained flows.
///
/// `active` indexes flows that are limited by some resource. Each iteration identifies the
/// tightest remaining resource, increases rates for all unfrozen flows by the same delta,
/// and freezes any flow that now sits on a saturated resource. When no constrained flows
/// remain, `rates` captures the final allocation (with `None` meaning unlimited).
fn compute_rates(active: &[usize], resources: &[Resource], rates: &mut [Option<Ratio>]) {
    if active.is_empty() {
        return;
    }

    // Track how much capacity each resource still has to hand out.
    let mut remaining: Vec<Ratio> = resources.iter().map(|res| res.capacity.clone()).collect();

    // `unfrozen[idx] == true` means the flow is still participating in progressive filling.
    let mut unfrozen = vec![false; rates.len()];
    for &idx in active {
        unfrozen[idx] = true;
    }
    let mut active_left = active.len();

    // Continue allocating until every flow is either unlimited or fully constrained.
    while active_left > 0 {
        let mut limiting = Vec::new();
        let mut min_delta: Option<Ratio> = None;

        for (res_idx, resource) in resources.iter().enumerate() {
            // Count how many still-active flows are drawing from this resource.
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

            // Potential additional rate every user could receive before hitting this limit.
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
            // Capacity exhausted: freeze every flow depending on the limiting resources.
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

        // Otherwise share the incremental `delta` evenly across every unfrozen flow.
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
            // Consume the matching share of resource capacity.
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

pub fn time_to_deplete(rate: &Rate, bytes: u128) -> Option<Duration> {
    match rate {
        Rate::Unlimited => Some(Duration::ZERO),
        Rate::Finite(ratio) => {
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

pub fn transfer(rate: &Rate, elapsed: Duration, carry: &mut u128, remaining: u128) -> u128 {
    if remaining == 0 {
        return 0;
    }

    match rate {
        Rate::Unlimited => {
            // No throttling – consume everything immediately.
            *carry = 0;
            remaining
        }
        Rate::Finite(ratio) => {
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
            // Any remainder from the integer division is stored in `carry` so the next tick can
            // honour fractional bytes-per-nanosecond that would otherwise be rounded away.
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
    use std::collections::BTreeMap;

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
            let Rate::Finite(ratio) = rate else {
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
        let Rate::Finite(ratio) = rate else {
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
        assert_eq!(allocations[&7], Rate::Unlimited);
    }

    #[test]
    fn transfer_accumulates_carry() {
        let ratio = Ratio { num: 1, den: 2 }; // 0.5 bytes per second
        let mut carry = 0;
        let rate = Rate::Finite(ratio);
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
        let rate = Rate::Finite(ratio);
        let time = time_to_deplete(&rate, 1_000).expect("finite time");
        assert_eq!(time.as_secs(), 2);
    }

    fn rate_of(map: &BTreeMap<u64, Rate>, id: u64) -> Ratio {
        match map.get(&id).expect("missing flow") {
            Rate::Finite(ratio) => ratio.clone(),
            Rate::Unlimited => panic!("unexpected unlimited rate"),
        }
    }

    #[test]
    fn three_peer_fair_sharing() {
        let flows = vec![
            Flow {
                id: 1,
                origin: 'A',
                recipient: 'B',
                requires_ingress: true,
            },
            Flow {
                id: 2,
                origin: 'A',
                recipient: 'B',
                requires_ingress: true,
            },
            Flow {
                id: 3,
                origin: 'B',
                recipient: 'C',
                requires_ingress: true,
            },
            Flow {
                id: 4,
                origin: 'A',
                recipient: 'C',
                requires_ingress: true,
            },
            Flow {
                id: 5,
                origin: 'C',
                recipient: 'B',
                requires_ingress: true,
            },
        ];

        let allocations = allocate(
            &flows,
            |origin: &char| match origin {
                'A' => Some(1_000_000), // 1_000 KB/s
                'B' => Some(750_000),
                'C' => Some(100_000),
                _ => None,
            },
            |recipient: &char| match recipient {
                'A' => Some(500_000),
                'B' => Some(250_000),
                'C' => Some(1_000_000),
                _ => None,
            },
        );

        let rate_ab1 = rate_of(&allocations, 1);
        assert_eq!(rate_ab1.num, 250_000);
        assert_eq!(rate_ab1.den, 3);

        let rate_ab2 = rate_of(&allocations, 2);
        assert_eq!(rate_ab2.num, 250_000);
        assert_eq!(rate_ab2.den, 3);

        let rate_ac = rate_of(&allocations, 4);
        assert_eq!(rate_ac.num, 500_000);
        assert_eq!(rate_ac.den, 1);

        let rate_bc = rate_of(&allocations, 3);
        assert_eq!(rate_bc.num, 500_000);
        assert_eq!(rate_bc.den, 1);

        let rate_cb = rate_of(&allocations, 5);
        assert_eq!(rate_cb.num, 250_000);
        assert_eq!(rate_cb.den, 3);
    }

    #[test]
    fn upstream_bottleneck_propagates() {
        let flows = vec![
            Flow {
                id: 1,
                origin: 'A',
                recipient: 'B',
                requires_ingress: true,
            },
            Flow {
                id: 2,
                origin: 'A',
                recipient: 'C',
                requires_ingress: true,
            },
        ];

        let allocations = allocate(
            &flows,
            |origin: &char| match origin {
                'A' => Some(1_000_000),
                'B' => Some(1_000_000),
                'C' => Some(1_000_000),
                _ => None,
            },
            |recipient: &char| match recipient {
                'A' => Some(500_000),
                'B' => Some(1_000),
                'C' => Some(500_000),
                _ => None,
            },
        );

        let rate_ab = rate_of(&allocations, 1);
        assert_eq!(rate_ab.num, 1_000);
        assert_eq!(rate_ab.den, 1);

        let rate_bc = rate_of(&allocations, 2);
        assert_eq!(rate_bc.num, 500_000);
        assert_eq!(rate_bc.den, 1);
    }

    #[test]
    fn limited_capacity_still_guarantees_fair_share() {
        let flows = vec![
            Flow {
                id: 1,
                origin: 'A',
                recipient: 'B',
                requires_ingress: true,
            },
            Flow {
                id: 2,
                origin: 'A',
                recipient: 'C',
                requires_ingress: true,
            },
        ];

        let allocations = allocate(
            &flows,
            |origin: &char| match origin {
                'A' => Some(50_000),
                'B' => Some(1_000_000),
                'C' => Some(1_000_000),
                _ => None,
            },
            |recipient: &char| match recipient {
                'A' => Some(500_000),
                'B' => Some(1_000),
                'C' => Some(500_000),
                _ => None,
            },
        );

        let rate_ab = rate_of(&allocations, 1);
        assert_eq!(rate_ab.num, 1_000);
        assert_eq!(rate_ab.den, 1);

        let rate_bc = rate_of(&allocations, 2);
        assert_eq!(rate_bc.num, 49_000);
        assert_eq!(rate_bc.den, 1);
    }
}
