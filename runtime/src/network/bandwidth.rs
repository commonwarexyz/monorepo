//! Max-min fair bandwidth allocation.
//!
//! The planner treats each sender's egress capacity and each receiver's ingress
//! capacity as a shared resource. It progressively raises every active flow's
//! rate until a resource is exhausted, freezes the flows using that resource,
//! and continues with the remaining flows.

use std::{cmp::Ordering, collections::BTreeMap, time::Duration};
use thiserror::Error;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// A non-negative fraction represented exactly as two `u128` values.
///
/// Fractions are always reduced to lowest terms. Arithmetic returns `None` if
/// the exact result cannot be represented by `u128`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fraction {
    numerator: u128,
    denominator: u128,
}

impl Fraction {
    /// Constructs a fraction, or returns `None` when `denominator` is zero.
    pub const fn new(numerator: u128, denominator: u128) -> Option<Self> {
        if denominator == 0 {
            return None;
        }

        let divisor = gcd(numerator, denominator);
        Some(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    /// Constructs an integer-valued fraction.
    pub const fn from_integer(value: u128) -> Self {
        Self {
            numerator: value,
            denominator: 1,
        }
    }

    /// Returns the numerator.
    pub const fn numerator(&self) -> u128 {
        self.numerator
    }

    /// Returns the denominator.
    pub const fn denominator(&self) -> u128 {
        self.denominator
    }

    /// Returns whether the fraction is zero.
    pub const fn is_zero(&self) -> bool {
        self.numerator == 0
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        let common = gcd(self.denominator, other.denominator);
        let self_scale = other.denominator / common;
        let other_scale = self.denominator / common;
        let numerator = self
            .numerator
            .checked_mul(self_scale)?
            .checked_add(other.numerator.checked_mul(other_scale)?)?;
        let denominator = self.denominator.checked_mul(self_scale)?;
        Self::new(numerator, denominator)
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        if self < other {
            return None;
        }

        let common = gcd(self.denominator, other.denominator);
        let self_scale = other.denominator / common;
        let other_scale = self.denominator / common;
        let left = self.numerator.checked_mul(self_scale)?;
        let right = other.numerator.checked_mul(other_scale)?;
        let numerator = left.checked_sub(right)?;
        let denominator = self.denominator.checked_mul(self_scale)?;
        Self::new(numerator, denominator)
    }

    fn checked_mul(self, other: Self) -> Option<Self> {
        let left_divisor = gcd(self.numerator, other.denominator);
        let right_divisor = gcd(other.numerator, self.denominator);
        let numerator =
            (self.numerator / left_divisor).checked_mul(other.numerator / right_divisor)?;
        let denominator =
            (self.denominator / right_divisor).checked_mul(other.denominator / left_divisor)?;
        Self::new(numerator, denominator)
    }

    fn checked_mul_integer(self, value: usize) -> Option<Self> {
        let value = value as u128;
        let divisor = gcd(value, self.denominator);
        let numerator = self.numerator.checked_mul(value / divisor)?;
        Self::new(numerator, self.denominator / divisor)
    }

    fn checked_div_integer(self, value: usize) -> Option<Self> {
        if value == 0 {
            return None;
        }

        let value = value as u128;
        let divisor = gcd(self.numerator, value);
        let denominator = self.denominator.checked_mul(value / divisor)?;
        Self::new(self.numerator / divisor, denominator)
    }

    fn checked_div(self, other: Self) -> Option<Self> {
        if other.is_zero() {
            return None;
        }

        let numerator_divisor = gcd(self.numerator, other.numerator);
        let denominator_divisor = gcd(other.denominator, self.denominator);
        let numerator = (self.numerator / numerator_divisor)
            .checked_mul(other.denominator / denominator_divisor)?;
        let denominator = (self.denominator / denominator_divisor)
            .checked_mul(other.numerator / numerator_divisor)?;
        Self::new(numerator, denominator)
    }

    fn ceil(self) -> u128 {
        let quotient = self.numerator / self.denominator;
        quotient + u128::from(!self.numerator.is_multiple_of(self.denominator))
    }
}

impl Ord for Fraction {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_ratios(
            self.numerator,
            self.denominator,
            other.numerator,
            other.denominator,
        )
    }
}

impl PartialOrd for Fraction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

const fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }

    if left == 0 { 1 } else { left }
}

fn compare_ratios(
    mut left_numerator: u128,
    mut left_denominator: u128,
    mut right_numerator: u128,
    mut right_denominator: u128,
) -> Ordering {
    let mut reverse = false;

    loop {
        let left_integer = left_numerator / left_denominator;
        let right_integer = right_numerator / right_denominator;
        let ordering = left_integer.cmp(&right_integer);
        if ordering != Ordering::Equal {
            return if reverse {
                ordering.reverse()
            } else {
                ordering
            };
        }

        let left_remainder = left_numerator % left_denominator;
        let right_remainder = right_numerator % right_denominator;
        match (left_remainder == 0, right_remainder == 0) {
            (true, true) => return Ordering::Equal,
            (true, false) => {
                return if reverse {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
            (false, true) => {
                return if reverse {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
            (false, false) => {}
        }

        left_numerator = left_denominator;
        left_denominator = left_remainder;
        right_numerator = right_denominator;
        right_denominator = right_remainder;
        reverse = !reverse;
    }
}

/// A flow competing for bandwidth.
#[derive(Clone, Debug)]
pub struct Flow<P> {
    /// Identifier copied into the allocation result.
    pub id: u64,
    /// Peer whose egress capacity the flow consumes.
    pub origin: P,
    /// Peer whose ingress capacity the flow consumes when delivered.
    pub recipient: P,
    /// Whether the flow reaches its recipient.
    ///
    /// Undelivered flows consume egress capacity but not ingress capacity.
    pub delivered: bool,
}

/// Throughput assigned to a flow, in bytes per second.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rate {
    /// No ingress or egress constraint limits the flow.
    Unlimited,
    /// An exact, finite throughput.
    Finite(Fraction),
}

/// Error returned when a bandwidth allocation cannot be represented.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AllocationError {
    /// More than one flow used the same identifier.
    #[error("duplicate flow identifier: {0}")]
    DuplicateFlow(u64),
}

#[derive(Debug)]
struct Resource {
    remaining: Fraction,
    members: Vec<usize>,
    active: usize,
}

impl Resource {
    const fn new(capacity: u128) -> Self {
        Self {
            remaining: Fraction::from_integer(capacity),
            members: Vec::new(),
            active: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Constraint<P> {
    Egress(P),
    Ingress(P),
}

#[derive(Debug)]
struct FlowState {
    resources: Vec<usize>,
    active: bool,
}

struct Planner<'a, P> {
    flows: &'a [Flow<P>],
    resources: Vec<Resource>,
    resource_indices: BTreeMap<Constraint<P>, usize>,
    states: Vec<FlowState>,
    rates: Vec<Option<Fraction>>,
    active: usize,
    fill: Fraction,
}

impl<'a, P: Clone + Ord> Planner<'a, P> {
    fn new<E, I>(flows: &'a [Flow<P>], egress_cap: &mut E, ingress_cap: &mut I) -> Self
    where
        E: FnMut(&P) -> Option<u128>,
        I: FnMut(&P) -> Option<u128>,
    {
        let mut planner = Self {
            flows,
            resources: Vec::new(),
            resource_indices: BTreeMap::new(),
            states: Vec::with_capacity(flows.len()),
            rates: vec![None; flows.len()],
            active: 0,
            fill: Fraction::from_integer(0),
        };
        planner.register(egress_cap, ingress_cap);
        planner
    }

    fn resource(&mut self, constraint: Constraint<P>, capacity: Option<u128>) -> Option<usize> {
        if let Some(index) = self.resource_indices.get(&constraint) {
            return Some(*index);
        }

        let capacity = capacity?;
        let index = self.resources.len();
        self.resources.push(Resource::new(capacity));
        self.resource_indices.insert(constraint, index);
        Some(index)
    }

    fn attach(&mut self, resource_index: usize, flow_index: usize, resources: &mut Vec<usize>) {
        let resource = &mut self.resources[resource_index];
        resource.members.push(flow_index);
        resource.active += 1;
        resources.push(resource_index);
    }

    fn register<E, I>(&mut self, egress_cap: &mut E, ingress_cap: &mut I)
    where
        E: FnMut(&P) -> Option<u128>,
        I: FnMut(&P) -> Option<u128>,
    {
        for (flow_index, flow) in self.flows.iter().enumerate() {
            let mut resources = Vec::with_capacity(2);

            let egress = self.resource(
                Constraint::Egress(flow.origin.clone()),
                egress_cap(&flow.origin),
            );
            if let Some(resource_index) = egress {
                self.attach(resource_index, flow_index, &mut resources);
            }

            if flow.delivered {
                let ingress = self.resource(
                    Constraint::Ingress(flow.recipient.clone()),
                    ingress_cap(&flow.recipient),
                );
                if let Some(resource_index) = ingress {
                    self.attach(resource_index, flow_index, &mut resources);
                }
            }

            let active = !resources.is_empty();
            self.active += usize::from(active);
            self.states.push(FlowState { resources, active });
        }
    }

    fn freeze(&mut self, resource_index: usize) {
        let members = self.resources[resource_index].members.clone();
        for flow_index in members {
            let state = &mut self.states[flow_index];
            if !state.active {
                continue;
            }

            self.rates[flow_index] = Some(self.fill);
            state.active = false;
            self.active -= 1;

            for &other_index in &state.resources {
                self.resources[other_index].active -= 1;
            }
        }
    }

    fn fill(&mut self) {
        while self.active > 0 {
            let mut delta = None;
            let mut limiting = Vec::new();

            for (index, resource) in self.resources.iter().enumerate() {
                if resource.active == 0 {
                    continue;
                }

                let share = resource
                    .remaining
                    .checked_div_integer(resource.active)
                    .expect("bandwidth allocation exceeds exact fraction range");
                match delta {
                    None => {
                        delta = Some(share);
                        limiting.push(index);
                    }
                    Some(current) => match share.cmp(&current) {
                        Ordering::Less => {
                            delta = Some(share);
                            limiting.clear();
                            limiting.push(index);
                        }
                        Ordering::Equal => limiting.push(index),
                        Ordering::Greater => {}
                    },
                }
            }

            let delta = delta.expect("active flow has no bandwidth constraint");
            self.fill = self
                .fill
                .checked_add(delta)
                .expect("bandwidth allocation exceeds exact fraction range");

            for resource in &mut self.resources {
                if resource.active == 0 {
                    continue;
                }

                let usage = delta
                    .checked_mul_integer(resource.active)
                    .expect("bandwidth allocation exceeds exact fraction range");
                resource.remaining = resource
                    .remaining
                    .checked_sub(usage)
                    .expect("bandwidth planner exceeded a resource capacity");
            }

            for resource_index in limiting {
                self.freeze(resource_index);
            }
        }
    }

    fn solve(mut self) -> BTreeMap<u64, Rate> {
        self.fill();

        self.flows
            .iter()
            .enumerate()
            .map(|(index, flow)| {
                let rate = self.rates[index].map_or(Rate::Unlimited, Rate::Finite);
                (flow.id, rate)
            })
            .collect()
    }
}

/// Computes an exact max-min fair allocation for `flows`.
///
/// A capacity of `None` is unlimited. Capacities are shared by all flows with
/// the same origin or recipient. The capacity callbacks must return a stable
/// value when called repeatedly for the same peer.
pub fn allocate<P, E, I>(
    flows: &[Flow<P>],
    mut egress_cap: E,
    mut ingress_cap: I,
) -> Result<BTreeMap<u64, Rate>, AllocationError>
where
    P: Clone + Ord,
    E: FnMut(&P) -> Option<u128>,
    I: FnMut(&P) -> Option<u128>,
{
    let mut identifiers = std::collections::BTreeSet::new();
    for flow in flows {
        if !identifiers.insert(flow.id) {
            return Err(AllocationError::DuplicateFlow(flow.id));
        }
    }

    Ok(Planner::new(flows, &mut egress_cap, &mut ingress_cap).solve())
}

/// Returns the time needed to transfer `remaining` bytes at `rate`.
///
/// The result rounds up to the first nanosecond at which the transfer is
/// complete. A zero finite rate never completes.
pub fn duration(rate: Rate, remaining: Fraction) -> Option<Duration> {
    if remaining.is_zero() {
        return Some(Duration::ZERO);
    }

    match rate {
        Rate::Unlimited => Some(Duration::ZERO),
        Rate::Finite(rate) if rate.is_zero() => None,
        Rate::Finite(rate) => {
            let seconds = remaining
                .checked_div(rate)
                .expect("transfer duration exceeds exact fraction range");
            let nanos = seconds
                .checked_mul(Fraction::from_integer(NANOS_PER_SECOND))
                .expect("transfer duration exceeds exact fraction range")
                .ceil();
            Some(duration_from_nanos(nanos))
        }
    }
}

/// Returns the work remaining after transferring at `rate` for `elapsed`.
///
/// Passing the returned fraction to the next call preserves partial-byte
/// progress exactly across scheduler ticks.
pub fn transfer(rate: Rate, elapsed: Duration, remaining: Fraction) -> Fraction {
    if remaining.is_zero() {
        return remaining;
    }

    let Rate::Finite(rate) = rate else {
        return Fraction::from_integer(0);
    };
    if rate.is_zero() || elapsed.is_zero() {
        return remaining;
    }

    let elapsed = Fraction::new(elapsed.as_nanos(), NANOS_PER_SECOND)
        .expect("nanoseconds per second is non-zero");
    let transferred = rate
        .checked_mul(elapsed)
        .expect("transfer progress exceeds exact fraction range");
    if transferred >= remaining {
        return Fraction::from_integer(0);
    }

    remaining
        .checked_sub(transferred)
        .expect("transferred amount was checked against remaining work")
}

const fn duration_from_nanos(nanos: u128) -> Duration {
    let seconds = nanos / NANOS_PER_SECOND;
    if seconds > u64::MAX as u128 {
        return Duration::MAX;
    }

    Duration::new(seconds as u64, (nanos % NANOS_PER_SECOND) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(id: u64, origin: char, recipient: char, delivered: bool) -> Flow<char> {
        Flow {
            id,
            origin,
            recipient,
            delivered,
        }
    }

    fn finite(allocations: &BTreeMap<u64, Rate>, id: u64) -> Fraction {
        let Rate::Finite(rate) = allocations[&id] else {
            panic!("flow {id} is unlimited");
        };
        rate
    }

    fn fraction(numerator: u128, denominator: u128) -> Fraction {
        Fraction::new(numerator, denominator).expect("non-zero denominator")
    }

    #[test]
    fn unlimited_flows() {
        let flows = [flow(1, 'A', 'B', true), flow(2, 'A', 'C', false)];

        let allocations = allocate(&flows, |_| None, |_| None).unwrap();

        assert_eq!(allocations[&1], Rate::Unlimited);
        assert_eq!(allocations[&2], Rate::Unlimited);
    }

    #[test]
    fn rejects_duplicate_flow_identifiers() {
        let flows = [flow(1, 'A', 'B', true), flow(1, 'A', 'C', true)];

        assert_eq!(
            allocate(&flows, |_| None, |_| None),
            Err(AllocationError::DuplicateFlow(1))
        );
    }

    #[test]
    fn shares_egress_capacity() {
        let flows = [
            flow(1, 'A', 'B', true),
            flow(2, 'A', 'C', true),
            flow(3, 'A', 'D', true),
        ];

        let allocations = allocate(&flows, |peer| (*peer == 'A').then_some(100), |_| None).unwrap();

        assert_eq!(finite(&allocations, 1), fraction(100, 3));
        assert_eq!(finite(&allocations, 2), fraction(100, 3));
        assert_eq!(finite(&allocations, 3), fraction(100, 3));
    }

    #[test]
    fn shares_ingress_capacity() {
        let flows = [
            flow(1, 'A', 'D', true),
            flow(2, 'B', 'D', true),
            flow(3, 'C', 'D', true),
        ];

        let allocations = allocate(&flows, |_| None, |peer| (*peer == 'D').then_some(10)).unwrap();

        assert_eq!(finite(&allocations, 1), fraction(10, 3));
        assert_eq!(finite(&allocations, 2), fraction(10, 3));
        assert_eq!(finite(&allocations, 3), fraction(10, 3));
    }

    #[test]
    fn combines_egress_and_ingress_bottlenecks() {
        let flows = [
            flow(1, 'A', 'X', true),
            flow(2, 'A', 'Y', true),
            flow(3, 'B', 'Y', true),
        ];

        let allocations = allocate(
            &flows,
            |peer| (*peer == 'A').then_some(100),
            |peer| match peer {
                'X' => Some(30),
                'Y' => Some(100),
                _ => None,
            },
        )
        .unwrap();

        assert_eq!(finite(&allocations, 1), Fraction::from_integer(30));
        assert_eq!(finite(&allocations, 2), Fraction::from_integer(50));
        assert_eq!(finite(&allocations, 3), Fraction::from_integer(50));
    }

    #[test]
    fn zero_capacity_stops_every_flow_using_it() {
        let flows = [flow(1, 'A', 'X', true), flow(2, 'A', 'Y', true)];

        let allocations = allocate(&flows, |peer| (*peer == 'A').then_some(0), |_| None).unwrap();

        assert_eq!(finite(&allocations, 1), Fraction::from_integer(0));
        assert_eq!(finite(&allocations, 2), Fraction::from_integer(0));
    }

    #[test]
    fn undelivered_flow_does_not_consume_ingress() {
        let flows = [flow(1, 'A', 'B', true), flow(2, 'A', 'B', false)];

        let allocations = allocate(
            &flows,
            |peer| (*peer == 'A').then_some(120),
            |peer| (*peer == 'B').then_some(60),
        )
        .unwrap();

        assert_eq!(finite(&allocations, 1), Fraction::from_integer(60));
        assert_eq!(finite(&allocations, 2), Fraction::from_integer(60));
    }

    #[test]
    fn duration_and_transfer_preserve_fractional_progress() {
        let rate = Rate::Finite(fraction(1, 2));
        let remaining = Fraction::from_integer(1);

        assert_eq!(duration(rate, remaining), Some(Duration::from_secs(2)));

        let remaining = transfer(rate, Duration::from_millis(500), remaining);
        assert_eq!(remaining, fraction(3, 4));
        assert_eq!(duration(rate, remaining), Some(Duration::from_millis(1500)));
    }

    #[test]
    fn unlimited_transfer_completes_without_elapsed_time() {
        let remaining = Fraction::from_integer(1);

        assert_eq!(duration(Rate::Unlimited, remaining), Some(Duration::ZERO));
        assert_eq!(
            transfer(Rate::Unlimited, Duration::ZERO, remaining),
            Fraction::from_integer(0)
        );
    }

    #[test]
    fn completed_transfer_needs_no_bandwidth() {
        assert_eq!(
            duration(
                Rate::Finite(Fraction::from_integer(0)),
                Fraction::from_integer(0)
            ),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn fraction_comparison_does_not_overflow() {
        let left = Fraction::new(u128::MAX, u128::MAX - 1).unwrap();
        let right = Fraction::new(u128::MAX - 1, u128::MAX).unwrap();

        assert!(left > right);
    }
}
