//! Deterministic scheduling for machine-owned semantic work.

use super::durability::EffectId;
use std::collections::VecDeque;

/// One synchronous protocol component serviced by the machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub(crate) enum ProtocolComponent {
    Finality,
    View,
    Da,
}

impl ProtocolComponent {
    /// The number of components.
    pub(crate) const COUNT: usize = 3;
    /// Every component, in wake order.
    pub(crate) const ALL: [Self; Self::COUNT] = [Self::Finality, Self::View, Self::Da];
}

/// One deduplicated unit of semantic work owned by the machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum WorkKey {
    /// Commit one validated local signing completion.
    CompleteEffect(EffectId),
    /// Commit the oldest parked recovery or aggregation completion.
    CompleteCrypto,
    /// Derive and stage the next protocol transition from absorbed facts.
    Drive(ProtocolComponent),
}

/// Effect keys reserved up front; larger outbox limits grow the queues on demand.
const MAX_PREALLOCATED_EFFECTS: usize = 1 << 16;

/// A FIFO that keeps at most one queued copy of each semantic work key.
pub(crate) struct Scheduler {
    ready: VecDeque<WorkKey>,
    queued_effects: Vec<EffectId>,
    crypto_queued: bool,
    components_queued: [bool; ProtocolComponent::COUNT],
}

impl Scheduler {
    pub(crate) fn new(max_complete_effects: usize) -> Self {
        let effects = max_complete_effects.min(MAX_PREALLOCATED_EFFECTS);
        // One ready key per queued effect, plus the crypto key and one key per component.
        Self {
            ready: VecDeque::with_capacity(effects + ProtocolComponent::ALL.len() + 1),
            queued_effects: Vec::with_capacity(effects),
            crypto_queued: false,
            components_queued: [false; ProtocolComponent::COUNT],
        }
    }

    /// Queues `key` at the tail unless it is already ready.
    pub(crate) fn enqueue(&mut self, key: WorkKey) {
        if !self.mark_queued(key) {
            return;
        }
        self.ready.push_back(key);
    }

    /// Queues `key` ahead of other ready work unless it is already queued.
    pub(crate) fn enqueue_front(&mut self, key: WorkKey) {
        if !self.mark_queued(key) {
            return;
        }
        self.ready.push_front(key);
    }

    /// Wakes every protocol component without creating a second component queue.
    pub(crate) fn enqueue_components(&mut self) {
        for component in ProtocolComponent::ALL {
            self.enqueue(WorkKey::Drive(component));
        }
    }

    /// Returns the key [`Self::pop`] removes next, without removing it.
    pub(crate) fn peek(&self) -> Option<WorkKey> {
        self.ready.front().copied()
    }

    /// Removes the oldest ready key and permits it to be requeued.
    pub(crate) fn pop(&mut self) -> Option<WorkKey> {
        let key = self.ready.pop_front()?;
        let removed = self.mark_ready(key);
        debug_assert!(removed, "ready work must have a membership entry");
        Some(key)
    }

    fn mark_queued(&mut self, key: WorkKey) -> bool {
        match key {
            WorkKey::CompleteEffect(id) => {
                let Err(position) = self.queued_effects.binary_search(&id) else {
                    return false;
                };
                self.queued_effects.insert(position, id);
                true
            }
            WorkKey::CompleteCrypto => !core::mem::replace(&mut self.crypto_queued, true),
            WorkKey::Drive(component) => {
                let queued = &mut self.components_queued[component as usize];
                !core::mem::replace(queued, true)
            }
        }
    }

    fn mark_ready(&mut self, key: WorkKey) -> bool {
        match key {
            WorkKey::CompleteEffect(id) => {
                let Ok(position) = self.queued_effects.binary_search(&id) else {
                    return false;
                };
                self.queued_effects.remove(position);
                true
            }
            WorkKey::CompleteCrypto => core::mem::replace(&mut self.crypto_queued, false),
            WorkKey::Drive(component) => {
                core::mem::replace(&mut self.components_queued[component as usize], false)
            }
        }
    }

    /// Returns whether at least one semantic work key is ready.
    pub(crate) fn has_work(&self) -> bool {
        !self.ready.is_empty()
    }
}

/// One externally supplied scheduler lane, in weighted-round-robin service order.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub(crate) enum Lane {
    PersistenceCompletion,
    LocalCompletion,
    Timer,
    ResolverResult,
    PeerObservation,
}

/// Maximum transition cost charged before the voter yields to the runtime.
pub(crate) const CORE_BUDGET: u32 = 256;

/// Work units one machine quantum may spend.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Budget(u32);

impl Budget {
    /// Returns the budget of one machine quantum.
    pub(crate) const fn quantum() -> Self {
        Self(CORE_BUDGET)
    }

    /// Returns the units left.
    pub(crate) const fn remaining(self) -> usize {
        self.0 as usize
    }

    /// Spends `units` and returns whether they fit; spends nothing when they do not.
    pub(crate) fn try_spend(&mut self, units: usize) -> bool {
        let Some(remaining) = u32::try_from(units)
            .ok()
            .and_then(|units| self.0.checked_sub(units))
        else {
            return false;
        };
        self.0 = remaining;
        true
    }

    /// Spends up to `units`, for work a pass already bounded by [`Self::remaining`].
    pub(crate) fn spend(&mut self, units: usize) {
        self.0 = self
            .0
            .saturating_sub(u32::try_from(units).unwrap_or(u32::MAX));
    }
}

/// Consecutive blocks of one producer chain a single DA-vote signing batch may carry.
pub(crate) const DA_VOTE_RUN: usize = 16;

/// Accounting for one weighted-round-robin cycle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceCycle {
    lane_credits: [u16; Lane::COUNT],
    core_credits: u32,
}

/// A charge the current service cycle cannot absorb.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServiceError {
    /// The lane has spent its weighted credit for this cycle.
    LaneExhausted,
    /// The cycle has spent its core budget; the voter must yield to the runtime.
    CoreBudgetExhausted,
    /// The transition cost does not fit a `u32` credit count.
    CostOverflow,
}

impl ServiceCycle {
    pub(crate) fn new() -> Self {
        Self {
            lane_credits: Lane::ALL.map(Lane::weight),
            core_credits: CORE_BUDGET,
        }
    }

    /// Charges one input of `lane` that processed `items` units, at one credit per unit and at
    /// least one.
    pub(crate) fn charge(&mut self, lane: Lane, items: usize) -> Result<(), ServiceError> {
        let lane_credit = &mut self.lane_credits[lane.index()];
        if *lane_credit == 0 {
            return Err(ServiceError::LaneExhausted);
        }
        let cost = u32::try_from(items.max(1)).map_err(|_| ServiceError::CostOverflow)?;
        let Some(remaining) = self.core_credits.checked_sub(cost) else {
            return Err(ServiceError::CoreBudgetExhausted);
        };
        *lane_credit -= 1;
        self.core_credits = remaining;
        Ok(())
    }

    pub(crate) const fn remaining_core(&self) -> u32 {
        self.core_credits
    }

    pub(crate) const fn remaining_lane(&self, lane: Lane) -> u16 {
        self.lane_credits[lane.index()]
    }
}

impl Default for ServiceCycle {
    fn default() -> Self {
        Self::new()
    }
}

/// Cursor for component and per-chain fairness.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct FairCursor {
    next: usize,
}

impl FairCursor {
    pub(crate) const fn new() -> Self {
        Self { next: 0 }
    }

    pub(crate) fn select(&mut self, ready: &[bool]) -> Option<usize> {
        if ready.is_empty() {
            return None;
        }
        for offset in 0..ready.len() {
            let index = self.next.checked_add(offset)? % ready.len();
            if ready[index] {
                self.next = (index + 1) % ready.len();
                return Some(index);
            }
        }
        None
    }
}

impl Default for FairCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl Lane {
    /// The number of lanes.
    pub(crate) const COUNT: usize = 5;
    /// Every lane, in service order.
    pub(crate) const ALL: [Self; Self::COUNT] = [
        Self::PersistenceCompletion,
        Self::LocalCompletion,
        Self::Timer,
        Self::ResolverResult,
        Self::PeerObservation,
    ];

    /// Returns the lane's position in [`Self::ALL`].
    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    /// Returns the lane's weighted-round-robin credit per cycle.
    ///
    /// Latency-sensitive internal completions receive more service without starving ingress.
    pub(crate) const fn weight(self) -> u16 {
        match self {
            Self::PersistenceCompletion | Self::LocalCompletion => 8,
            Self::Timer | Self::ResolverResult => 4,
            Self::PeerObservation => 2,
        }
    }

    /// Returns whether a peer, rather than the machine itself, chooses this lane's payload sizes.
    ///
    /// Only these lanes need a byte ceiling. Every other lane carries completions of work the
    /// machine issued and already counted, so a byte budget there bounds nothing the item ceiling
    /// does not, while making an over-count in a completion payload fatal to the voter.
    pub(crate) const fn peer_supplied(self) -> bool {
        matches!(self, Self::ResolverResult | Self::PeerObservation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_effect_bound_cannot_overflow_scheduler_capacity() {
        let scheduler = Scheduler::new(usize::MAX);
        assert!(!scheduler.has_work());
    }

    #[test]
    fn lanes_index_their_position_in_service_order() {
        for (index, lane) in Lane::ALL.into_iter().enumerate() {
            assert_eq!(lane.index(), index);
        }
        assert_eq!(Lane::ALL.len(), Lane::COUNT);
    }

    #[test]
    fn budget_spends_all_or_nothing() {
        let mut budget = Budget::quantum();
        let quantum = budget.remaining();
        assert!(!budget.try_spend(quantum + 1));
        assert_eq!(budget.remaining(), quantum);
        assert!(!budget.try_spend(usize::MAX));
        assert_eq!(budget.remaining(), quantum);
        assert!(budget.try_spend(quantum - 1));
        assert_eq!(budget.remaining(), 1);
        assert!(budget.try_spend(1));
        assert_eq!(budget.remaining(), 0);
        assert!(budget.try_spend(0));
        budget.spend(usize::MAX);
        assert_eq!(budget.remaining(), 0);
    }
}
