//! Max-min fair bandwidth planner.
//!
//! The planner performs progressive filling over a set of active flows to
//! compute per-flow transmission rates that respect both sender egress limits
//! and receiver ingress limits (to provide max-min fairness). The caller is responsible
//! for advancing flow progress according to the returned rates and invoking the planner
//! whenever the active set changes (for example when a message finishes or a new message
//! arrives).

use commonware_utils::{time::NANOS_PER_SEC, DurationExt, Ratio};
use std::{cmp::Ordering, collections::BTreeMap, time::Duration};

/// Minimal description of a simulated transmission path.
///
/// `delivered == false` means the flow only exercises the sender egress path (for example,
/// packets that will be dropped before they reach the recipient) so we avoid charging ingress
/// capacity for it.
#[derive(Clone, Debug)]
pub struct Flow<P> {
    pub id: u64,
    pub origin: P,
    pub recipient: P,
    pub delivered: bool,
}

/// Resulting per-flow throughput expressed as bytes/second.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rate {
    Unlimited,
    Finite(Ratio),
}

/// Shared capacity constraint (either egress or ingress) tracked by the planner.
///
/// `remaining` tracks the unassigned bytes/second, `members` contains the flows that consume the
/// resource, and `active` counts how many of those flows are still eligible for additional
/// bandwidth in the current filling round.
#[derive(Debug)]
struct Resource {
    remaining: Ratio,
    members: Vec<usize>,
    active: usize,
}

impl Resource {
    fn new(limit: u128) -> Self {
        Self {
            remaining: Ratio::from_int(limit),
            members: Vec::new(),
            active: 0,
        }
    }
}

/// Identifier used to deduplicate resource entries across flows.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Constraint<P> {
    Egress(P),
    Ingress(P),
}

/// Tracks the constraints participating in a flow and whether it is still constrained.
struct State {
    resources: Vec<usize>,
    limited: bool,
    active: bool,
}

impl State {
    fn new() -> Self {
        Self {
            resources: Vec::new(),
            limited: false,
            active: false,
        }
    }
}

/// Planner once all flows have been registered.
struct Planner<'a, P> {
    flows: &'a [Flow<P>],
    resources: Vec<Resource>,
    indices: BTreeMap<Constraint<P>, usize>,
    states: Vec<State>,
    rates: Vec<Option<Ratio>>,
    active: usize,
    fill: Ratio,
}

impl<'a, P: Clone + Ord> Planner<'a, P> {
    /// Build and register resources for all flows up front.
    fn new<E, I>(flows: &'a [Flow<P>], egress_limit: &mut E, ingress_limit: &mut I) -> Self
    where
        E: FnMut(&P) -> Option<u128>,
        I: FnMut(&P) -> Option<u128>,
    {
        let mut planner = Self {
            flows,
            resources: Vec::new(),
            indices: BTreeMap::new(),
            states: Vec::with_capacity(flows.len()),
            rates: vec![None; flows.len()],
            active: 0,
            fill: Ratio::zero(),
        };
        planner.register(egress_limit, ingress_limit);
        planner
    }

    /// Ensure a resource entry exists, returning its index if the resource is rate-limited.
    ///
    /// Unbounded resources return `None`, allowing callers to skip any additional bookkeeping for
    /// flows that touch them.
    fn track(&mut self, constraint: Constraint<P>, limit: Option<u128>) -> Option<usize> {
        if let Some(index) = self.indices.get(&constraint) {
            return Some(*index);
        }
        let limit = limit?;
        let idx = self.resources.len();
        self.resources.push(Resource::new(limit));
        self.indices.insert(constraint, idx);
        Some(idx)
    }

    /// Link a flow to a resource, marking it as constrained.
    fn attach(&mut self, resource_idx: usize, flow_idx: usize, state: &mut State) {
        let resource = &mut self.resources[resource_idx];
        resource.members.push(flow_idx);
        resource.active += 1;

        // We have to update both the resource and flow views so freezing can walk in either
        // direction without extra lookups.
        state.resources.push(resource_idx);
        state.limited = true;
    }

    /// Register each flow with the constrained resources it depends on. Resources without limits are ignored.
    fn register<E, I>(&mut self, egress_limit: &mut E, ingress_limit: &mut I)
    where
        E: FnMut(&P) -> Option<u128>,
        I: FnMut(&P) -> Option<u128>,
    {
        for (flow_idx, flow) in self.flows.iter().enumerate() {
            let mut state = State::new();

            // Register the flow with its egress resource if the sender is bandwidth-limited.
            if let Some(resource_idx) = self.track(
                Constraint::Egress(flow.origin.clone()),
                egress_limit(&flow.origin),
            ) {
                self.attach(resource_idx, flow_idx, &mut state);
            }

            // Only track ingress when the recipient actually needs to receive the bytes.
            if flow.delivered {
                // Register the flow with its ingress resource if the recipient is bandwidth-limited.
                if let Some(resource_idx) = self.track(
                    Constraint::Ingress(flow.recipient.clone()),
                    ingress_limit(&flow.recipient),
                ) {
                    self.attach(resource_idx, flow_idx, &mut state);
                }
            }

            // The flow participates in progressive filling until one of its constraints saturates.
            if state.limited {
                state.active = true;
                self.active += 1;
            }
            self.states.push(state);
        }
    }

    /// Freeze all flows that rely on a saturated resource.
    fn freeze(&mut self, res_idx: usize) {
        let members = self.resources[res_idx].members.clone();
        for flow_idx in members {
            self.deactivate(flow_idx);
        }
    }

    /// Finalize the rate for `flow_idx` and update every referenced resource.
    ///
    /// The flow's share at the moment of freezing becomes its permanent rate; afterwards we
    /// subtract it from every referenced resource so the next progressive-filling iteration only
    /// considers the remaining active flows.
    fn deactivate(&mut self, flow_idx: usize) {
        let state = &mut self.states[flow_idx];
        if !state.active {
            return;
        }

        // The flow's max-min allocation equals the current fill level.
        self.rates[flow_idx] = Some(self.fill.clone());
        state.active = false;
        self.active -= 1;

        for &res_idx in &state.resources {
            let resource = &mut self.resources[res_idx];
            if resource.active > 0 {
                // Stop counting the flow toward future shares once it is frozen.
                resource.active -= 1;
            }
        }
    }

    /// Run the progressive filling algorithm until every constrained flow is frozen.
    fn fill(&mut self) {
        if self.active == 0 {
            return;
        }

        let mut limiting = Vec::new();
        while self.active > 0 {
            // Reset the limiting set (avoids reallocation)
            limiting.clear();
            let mut min_delta: Option<Ratio> = None;

            // Step 1: among all resources still serving active flows, locate the smallest per-flow
            // headroom (i.e. the next constraint that will be hit if we increase every active flow
            // uniformly).
            for (res_idx, resource) in self.resources.iter().enumerate() {
                if resource.active == 0 {
                    continue;
                }

                // This resource is already saturated; any flow touching it freezes immediately.
                if resource.remaining.is_zero() {
                    limiting.clear();
                    limiting.push(res_idx);
                    min_delta = Some(Ratio::zero());
                    break;
                }

                let share = resource.remaining.div_int(resource.active as u128);
                match &min_delta {
                    None => {
                        // First candidate: provisionally treat it as the tightest constraint.
                        min_delta = Some(share);
                        limiting.clear();
                        limiting.push(res_idx);
                    }
                    Some(current) => match share.cmp(current) {
                        Ordering::Less => {
                            // Found a tougher constraint, so reset the limiting set.
                            min_delta = Some(share);
                            limiting.clear();
                            limiting.push(res_idx);
                        }
                        Ordering::Equal => limiting.push(res_idx),
                        Ordering::Greater => {}
                    },
                }
            }

            // Step 2: if the limiting resources still have headroom, advance every active flow by
            // `delta`. If `delta` is zero we already exhausted a resource, so we skip the advance
            // and immediately freeze the affected flows instead.
            let delta = match min_delta {
                Some(delta) => delta,
                None => {
                    // Every active flow should have been tied to at least one limited resource.
                    assert_eq!(self.active, 0, "active flows without constraints");
                    break;
                }
            };

            // Capacity was already consumed, so immediately freeze the affected flows.
            if delta.is_zero() {
                for &res_idx in &limiting {
                    self.freeze(res_idx);
                }
                continue;
            }

            // Raise the shared fill level; individual rates are materialized on freeze.
            self.fill.add_assign(&delta);
            let mut saturated = Vec::new();
            for (res_idx, resource) in self.resources.iter_mut().enumerate() {
                if resource.active == 0 {
                    continue;
                }

                // Charge each resource for the uniform allocation it just handed out.
                let usage = delta.mul_int(resource.active as u128);
                if usage.is_zero() {
                    continue;
                }

                // Track newly saturated resources so their flows freeze this iteration.
                resource.remaining.sub_assign(&usage);
                if resource.remaining.is_zero() {
                    saturated.push(res_idx);
                }
            }
            saturated.extend(limiting.iter().copied());
            if saturated.is_empty() {
                continue;
            }

            // Step 3: freeze every flow touching the resources that just saturated so they are not
            // considered in the next iteration.
            saturated.sort();
            saturated.dedup();
            for res_idx in saturated {
                self.freeze(res_idx);
            }
        }
    }

    /// Consume the planner, finalising the rate for every flow and returning the result map.
    fn solve(mut self) -> BTreeMap<u64, Rate> {
        // Run the progressive filling algorithm until every constrained flow is frozen.
        self.fill();

        // Finalize the rates for every flow.
        let mut result = BTreeMap::new();
        for (idx, flow) in self.flows.iter().enumerate() {
            let rate = match &self.rates[idx] {
                Some(ratio) => Rate::Finite(ratio.clone()),
                None => Rate::Unlimited,
            };
            result.insert(flow.id, rate);
        }
        result
    }

    #[cfg(test)]
    fn resource_count(&self) -> usize {
        self.resources.len()
    }

    #[cfg(test)]
    fn resource_members(&self, idx: usize) -> &[usize] {
        &self.resources[idx].members
    }

    #[cfg(test)]
    fn resource_active(&self, idx: usize) -> usize {
        self.resources[idx].active
    }

    #[cfg(test)]
    fn states(&self) -> &[State] {
        &self.states
    }

    #[cfg(test)]
    fn active_flows(&self) -> usize {
        self.active
    }

    #[cfg(test)]
    fn rates_slice(&self) -> &[Option<Ratio>] {
        &self.rates
    }
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
    if flows.is_empty() {
        return BTreeMap::new();
    }

    // Register the flows and solve. Construction hydrates the planner with all resource
    // membership data, and `solve` consumes it to run progressive filling and return the final map.
    let planner = Planner::new(flows, &mut egress_limit, &mut ingress_limit);
    planner.solve()
}

/// Calculate the time it will take to deplete a given amount of capacity at some [Rate].
///
/// The computation rounds up so callers receive the minimum duration that guarantees at least the
/// requested number of bytes were transmitted.
pub fn lifetime(rate: &Rate, bytes: u128) -> Option<Duration> {
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
                // `ratio` encodes throughput as `num/den` bytes per second. We convert the
                // requested `bytes` into the equivalent duration in nanoseconds by computing
                // `bytes * den / num` seconds and scaling by `NANOS_PER_SEC`, rounding up so the
                // caller receives the minimum time that guarantees the requested bytes were sent.
                let numerator = bytes
                    .saturating_mul(ratio.den)
                    .saturating_mul(NANOS_PER_SEC);
                let ns = if ratio.num == 0 {
                    u128::MAX
                } else {
                    numerator.div_ceil(ratio.num)
                };
                Some(Duration::from_nanos_saturating(ns))
            }
        }
    }
}

/// Calculate the number of bytes that can be transferred in a given duration at some [Rate],
/// accounting for any fractional bytes-per-nanosecond that would otherwise be rounded away.
///
/// The caller supplies `carry` to preserve sub-byte precision across repeated invocations (useful
/// when advancing simulation time in small quanta) and can inspect the return value to learn how
/// much progress a flow made before an interruption.
pub fn transfer(rate: &Rate, elapsed: Duration, carry: &mut u128, remaining: u128) -> u128 {
    if remaining == 0 {
        return 0;
    }

    match rate {
        Rate::Unlimited => {
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

            let denom = ratio.den.saturating_mul(NANOS_PER_SEC);
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
                delivered: true,
            },
            Flow {
                id: 2,
                origin: 1,
                recipient: 11,
                delivered: true,
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
            delivered: true,
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
            delivered: false,
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
        let time = lifetime(&rate, 1_000).expect("finite time");
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
                delivered: true,
            },
            Flow {
                id: 2,
                origin: 'A',
                recipient: 'B',
                delivered: true,
            },
            Flow {
                id: 3,
                origin: 'B',
                recipient: 'C',
                delivered: true,
            },
            Flow {
                id: 4,
                origin: 'A',
                recipient: 'C',
                delivered: true,
            },
            Flow {
                id: 5,
                origin: 'C',
                recipient: 'B',
                delivered: true,
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
                delivered: true,
            },
            Flow {
                id: 2,
                origin: 'A',
                recipient: 'C',
                delivered: true,
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
                delivered: true,
            },
            Flow {
                id: 2,
                origin: 'A',
                recipient: 'C',
                delivered: true,
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

    #[test]
    fn planner_skips_unlimited_resources() {
        let flows = vec![Flow {
            id: 99,
            origin: 1u8,
            recipient: 2u8,
            delivered: true,
        }];

        let mut egress = unlimited();
        let mut ingress = unlimited();
        let planner = Planner::new(&flows, &mut egress, &mut ingress);

        assert_eq!(planner.resource_count(), 0);
        assert!(planner.states().iter().all(|state| !state.limited));
        assert_eq!(planner.active_flows(), 0);
    }

    #[test]
    fn planner_tracks_shared_resource_membership() {
        let flows = vec![
            Flow {
                id: 1,
                origin: 1u8,
                recipient: 10u8,
                delivered: true,
            },
            Flow {
                id: 2,
                origin: 1u8,
                recipient: 11u8,
                delivered: true,
            },
        ];

        let mut egress = constant(1_000);
        let mut ingress = unlimited();
        let planner = Planner::new(&flows, &mut egress, &mut ingress);

        assert_eq!(planner.resource_count(), 1);
        assert_eq!(planner.resource_members(0), &[0, 1]);
        assert_eq!(planner.resource_active(0), 2);
        assert!(planner.states().iter().all(|state| state.active));
    }

    #[test]
    fn planner_freeze_clears_active_counts() {
        let flows = vec![
            Flow {
                id: 1,
                origin: 1u8,
                recipient: 2u8,
                delivered: true,
            },
            Flow {
                id: 2,
                origin: 1u8,
                recipient: 3u8,
                delivered: true,
            },
        ];

        let mut egress = constant(1_000);
        let mut ingress = unlimited();
        let mut planner = Planner::new(&flows, &mut egress, &mut ingress);
        assert_eq!(planner.active_flows(), 2);

        // Freezing the shared egress resource should freeze both flows and zero the counters.
        planner.freeze(0);

        assert_eq!(planner.resource_active(0), 0);
        assert_eq!(planner.active_flows(), 0);
        assert!(planner
            .rates_slice()
            .iter()
            .filter_map(|opt| opt.as_ref())
            .all(|ratio| ratio.is_zero()));
    }
}
