//! Max-min fair bandwidth planner.
//!
//! The planner progressively fills a set of active flows to compute per-flow
//! transmission rates that respect both sender egress limits and receiver ingress limits
//! (to provide max-min fairness). The caller is responsible for advancing flow progress
//! according to the returned rates and invoking the planner whenever the active set
//! changes (for example when a message finishes or a new message arrives).

use commonware_utils::{time::NANOS_PER_SEC, BigRationalExt, DurationExt};
use num_rational::BigRational;
use num_traits::Zero;
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
    Finite(BigRational),
}

/// Shared capacity constraint (either egress or ingress) tracked by the planner.
///
/// `remaining` tracks the unassigned bytes/second, `members` contains the flows that consume the
/// resource, and `active` counts how many of those flows are still eligible for additional
/// bandwidth in the current filling round.
#[derive(Debug)]
struct Resource {
    remaining: BigRational,
    members: Vec<usize>,
    active: usize,
}

impl Resource {
    fn new(limit: u128) -> Self {
        Self {
            remaining: BigRational::from_u128(limit),
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
    const fn new() -> Self {
        Self {
            resources: Vec::new(),
            limited: false,
            active: false,
        }
    }
}

/// Allocate bandwidth for a set of flows given some set of capacity constraints.
struct Planner<'a, P> {
    /// Caller-supplied flow metadata (immutable throughout the run).
    flows: &'a [Flow<P>],
    /// All constrained resources participating in this planning step.
    resources: Vec<Resource>,
    /// Reverse index from `(peer, direction)` to the corresponding resource slot.
    indices: BTreeMap<Constraint<P>, usize>,
    /// Per-flow membership and bookkeeping flags used during progressive filling.
    states: Vec<State>,
    /// Final per-flow throughput; `None` indicates an unlimited flow.
    rates: Vec<Option<BigRational>>,
    /// Number of flows still taking part in the current filling round.
    active: usize,
    /// Shared fill level applied to every active flow.
    fill: BigRational,
}

impl<'a, P: Clone + Ord> Planner<'a, P> {
    /// Build and register resources for all flows up front.
    fn new<E, I>(flows: &'a [Flow<P>], egress_cap: &mut E, ingress_cap: &mut I) -> Self
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
            fill: BigRational::zero(),
        };
        planner.register(egress_cap, ingress_cap);
        planner
    }

    /// Ensure a resource entry exists, returning its index if the resource is rate-limited.
    ///
    /// Unbounded resources return `None`, allowing callers to skip any additional bookkeeping for
    /// flows that touch them.
    fn constrain(&mut self, constraint: Constraint<P>, limit: Option<u128>) -> Option<usize> {
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
    fn register<E, I>(&mut self, egress_cap: &mut E, ingress_cap: &mut I)
    where
        E: FnMut(&P) -> Option<u128>,
        I: FnMut(&P) -> Option<u128>,
    {
        for (flow_idx, flow) in self.flows.iter().enumerate() {
            let mut state = State::new();

            // Register the flow with its egress resource if the sender is bandwidth-limited.
            if let Some(resource_idx) = self.constrain(
                Constraint::Egress(flow.origin.clone()),
                egress_cap(&flow.origin),
            ) {
                self.attach(resource_idx, flow_idx, &mut state);
            }

            // Only track ingress when the recipient actually needs to receive the bytes.
            if flow.delivered {
                // Register the flow with its ingress resource if the recipient is bandwidth-limited.
                if let Some(resource_idx) = self.constrain(
                    Constraint::Ingress(flow.recipient.clone()),
                    ingress_cap(&flow.recipient),
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
            // Finalize the rate for `flow_idx` and update every referenced resource.
            //
            // The flow's share at the moment of freezing becomes its permanent rate; afterwards we
            // subtract it from every referenced resource so the next progressive-filling iteration only
            // considers the remaining active flows.
            let state = &mut self.states[flow_idx];
            if !state.active {
                continue;
            }

            // The flow's max-min allocation equals the current fill level.
            self.rates[flow_idx] = Some(self.fill.clone());
            state.active = false;
            self.active -= 1;

            // Subtract the flow's share from other referenced resources
            for &other_res_idx in &state.resources {
                let resource = &mut self.resources[other_res_idx];
                if resource.active > 0 {
                    // Stop counting the flow toward future shares once it is frozen.
                    resource.active -= 1;
                }
            }
        }
    }

    /// Run the progressive filling algorithm until every constrained flow is frozen.
    fn fill(&mut self) {
        while self.active > 0 {
            let mut limiting = Vec::new();
            let mut min_delta: Option<BigRational> = None;

            // Step 1: among all resources still serving active flows, locate the smallest per-flow
            // headroom (i.e. the next constraint that will be hit if we increase every active flow
            // uniformly).
            for (res_idx, resource) in self.resources.iter().enumerate() {
                if resource.active == 0 {
                    continue;
                }

                // This resource is already saturated; any flow touching it should freeze immediately.
                if resource.remaining.is_zero() {
                    limiting.clear();
                    limiting.push(res_idx);
                    min_delta = Some(BigRational::zero());
                    break;
                }

                let share = &resource.remaining / BigRational::from_usize(resource.active);
                match &min_delta {
                    None => {
                        // First candidate: provisionally treat it as the tightest constraint.
                        min_delta = Some(share);
                        limiting.clear();
                        limiting.push(res_idx);
                    }
                    Some(current) => match share.cmp(current) {
                        Ordering::Less => {
                            // Found a tougher constraint (lower headroom), so reset the limiting set.
                            min_delta = Some(share);
                            limiting.clear();
                            limiting.push(res_idx);
                        }
                        Ordering::Equal => limiting.push(res_idx),
                        Ordering::Greater => {
                            // This resource still has extra headroom relative to the current
                            // bottleneck, so we leave it out of the limiting set and let it
                            // keep contributing capacity in this round.
                        }
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
            if delta.is_zero() {
                for &res_idx in &limiting {
                    self.freeze(res_idx);
                }
                continue;
            }

            // Raise the shared fill level; individual rates are materialized on freeze.
            self.fill += &delta;
            let mut saturated = Vec::new();
            for (res_idx, resource) in self.resources.iter_mut().enumerate() {
                // Skip resources that are not active.
                if resource.active == 0 {
                    continue;
                }

                // Charge each resource for the uniform allocation it just handed out.
                let usage = &delta * BigRational::from_usize(resource.active);
                if usage.is_zero() {
                    continue;
                }

                // Track newly saturated resources so their flows freeze this iteration.
                resource.remaining -= usage;
                if resource.remaining.is_zero() {
                    saturated.push(res_idx);
                }
            }
            saturated.extend(limiting);
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

    /// Consume the planner, finalizing the rate for every flow and returning the result map.
    fn solve(mut self) -> BTreeMap<u64, Rate> {
        // Run the progressive filling algorithm until every constrained flow is frozen.
        self.fill();

        // Finalize the rates for every flow.
        let mut result = BTreeMap::new();
        for (idx, flow) in self.flows.iter().enumerate() {
            let rate = self.rates[idx]
                .as_ref()
                .map_or(Rate::Unlimited, |ratio| Rate::Finite(ratio.clone()));
            result.insert(flow.id, rate);
        }
        result
    }

    #[cfg(test)]
    fn resources(&self) -> &[Resource] {
        &self.resources
    }

    #[cfg(test)]
    fn states(&self) -> &[State] {
        &self.states
    }

    #[cfg(test)]
    const fn active(&self) -> usize {
        self.active
    }

    #[cfg(test)]
    fn rates(&self) -> &[Option<BigRational>] {
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
    mut egress_cap: E,
    mut ingress_cap: I,
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
    let planner = Planner::new(flows, &mut egress_cap, &mut ingress_cap);
    planner.solve()
}

/// Calculate the time it will take to deplete a given amount of capacity at some [Rate].
///
/// The computation rounds up so callers receive the minimum duration that guarantees at least the
/// requested amount of work was transmitted.
pub fn duration(rate: &Rate, remaining: &BigRational) -> Option<Duration> {
    match rate {
        Rate::Unlimited => Some(Duration::ZERO),
        Rate::Finite(rate) => {
            // If the rate is zero, the transfer will never complete.
            if rate.is_zero() {
                return None;
            }

            // Find the minimum number of nanoseconds that will complete the transfer (rounding up to cover
            // fractional progress).
            let seconds = remaining / rate;
            let nanos = seconds * BigRational::from_u128(NANOS_PER_SEC);
            let ns = nanos.ceil_to_u128()?;
            Some(Duration::from_nanos_saturating(ns))
        }
    }
}

/// Calculate the remaining work after transferring data for `elapsed` at the provided [Rate].
///
/// Feed the returned ratio back into subsequent calls to preserve fractional progress across
/// discrete scheduling ticks.
pub fn transfer(rate: &Rate, elapsed: Duration, mut remaining: BigRational) -> BigRational {
    if remaining.is_zero() {
        return remaining;
    }

    match rate {
        Rate::Unlimited => BigRational::zero(),
        Rate::Finite(ratio) => {
            if ratio.is_zero() || elapsed.is_zero() {
                return remaining;
            }

            let delta_ns = elapsed.as_nanos();
            if delta_ns == 0 {
                return remaining;
            }

            let elapsed = BigRational::from_frac_u128(delta_ns, NANOS_PER_SEC);
            let usage = ratio * &elapsed;
            if usage >= remaining {
                return BigRational::zero();
            }

            remaining -= usage;
            remaining
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_rational::BigRational;
    use std::collections::BTreeMap;

    fn constant(limit: u128) -> impl FnMut(&u8) -> Option<u128> {
        move |_| Some(limit)
    }

    fn unlimited() -> impl FnMut(&u8) -> Option<u128> {
        move |_| None
    }

    fn assert_rational_eq(r: &BigRational, num: u64, den: u64) {
        assert_eq!(r, &BigRational::from_frac_u64(num, den));
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
            assert_rational_eq(ratio, 500, 1);
        }
    }

    #[test]
    fn ingress_cap_enforced() {
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
        assert_rational_eq(ratio, 2_000, 1);
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
        let ratio = BigRational::from_frac_u64(1, 2); // 0.5 bytes per second
        let rate = Rate::Finite(ratio);
        let initial = BigRational::from_u128(10);

        let after_short = transfer(&rate, Duration::from_millis(500), initial);
        assert_eq!(after_short, BigRational::from_frac_u64(39, 4));

        let after_long = transfer(&rate, Duration::from_millis(1500), after_short);
        assert_eq!(after_long, BigRational::from_u128(9));
    }

    #[test]
    fn finish_duration_accounts_for_fractional_progress() {
        let rate = Rate::Finite(BigRational::from_frac_u64(1, 2));
        let initial = BigRational::from_u128(1);
        let partial = transfer(&rate, Duration::from_millis(500), initial.clone());
        assert_eq!(partial, BigRational::from_frac_u64(3, 4));

        let duration_full = duration(&rate, &initial).expect("finite duration");
        assert_eq!(duration_full, Duration::from_secs(2));

        let finish = duration(&rate, &partial).expect("finish duration");
        assert_eq!(finish, Duration::from_millis(1500));
        assert!(finish < duration_full);
    }

    #[test]
    fn bandwidth_duration() {
        let ratio = BigRational::from_u128(500);
        let rate = Rate::Finite(ratio);
        let time = duration(&rate, &BigRational::from_u128(1_000)).expect("finite time");
        assert_eq!(time.as_secs(), 2);
    }

    fn rate_of(map: &BTreeMap<u64, Rate>, id: u64) -> BigRational {
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
        assert_rational_eq(&rate_ab1, 250_000, 3);

        let rate_ab2 = rate_of(&allocations, 2);
        assert_rational_eq(&rate_ab2, 250_000, 3);

        let rate_ac = rate_of(&allocations, 4);
        assert_rational_eq(&rate_ac, 500_000, 1);

        let rate_bc = rate_of(&allocations, 3);
        assert_rational_eq(&rate_bc, 500_000, 1);

        let rate_cb = rate_of(&allocations, 5);
        assert_rational_eq(&rate_cb, 250_000, 3);
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
        assert_rational_eq(&rate_ab, 1_000, 1);

        let rate_bc = rate_of(&allocations, 2);
        assert_rational_eq(&rate_bc, 500_000, 1);
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
        assert_rational_eq(&rate_ab, 1_000, 1);

        let rate_bc = rate_of(&allocations, 2);
        assert_rational_eq(&rate_bc, 49_000, 1);
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

        assert_eq!(planner.resources().len(), 0);
        assert!(planner.states().iter().all(|state| !state.limited));
        assert_eq!(planner.active(), 0);
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

        let resources = planner.resources();
        assert_eq!(resources.len(), 1);
        let resource = &resources[0];
        assert_eq!(resource.members, vec![0, 1]);
        assert_eq!(resource.active, 2);
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
        assert_eq!(planner.active(), 2);

        // Freezing the shared egress resource should freeze both flows and zero the counters.
        planner.freeze(0);

        let resources = planner.resources();
        assert_eq!(resources[0].active, 0);
        assert_eq!(planner.active(), 0);
        assert!(planner
            .rates()
            .iter()
            .filter_map(|opt| opt.as_ref())
            .all(|ratio| ratio.is_zero()));
    }
}
