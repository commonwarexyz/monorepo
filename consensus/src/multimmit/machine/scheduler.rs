//! Deterministic scheduling for machine-owned semantic work.

use super::EffectId;
use std::collections::VecDeque;

/// One synchronous protocol component serviced by the machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProtocolComponent {
    Finality,
    View,
    Da,
}

impl ProtocolComponent {
    pub(crate) const ALL: [Self; 3] = [Self::Finality, Self::View, Self::Da];
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

/// A FIFO that keeps at most one queued copy of each semantic work key.
pub(crate) struct Scheduler {
    ready: VecDeque<WorkKey>,
    queued_effects: Vec<EffectId>,
    crypto_queued: bool,
    components_queued: [bool; 3],
}

impl Scheduler {
    pub(crate) fn new(max_complete_effects: usize) -> Self {
        let mut ready = VecDeque::new();
        let mut queued_effects = Vec::new();
        if let Some(capacity) = max_complete_effects.checked_add(ProtocolComponent::ALL.len() + 1) {
            // Capacity is an optimization. Explicit test limits may be intentionally wider than
            // the address space, so a failed reservation must not change machine construction.
            let _ = ready.try_reserve_exact(capacity);
        }
        let _ = queued_effects.try_reserve_exact(max_complete_effects);
        Self {
            ready,
            queued_effects,
            crypto_queued: false,
            components_queued: [false; 3],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_effect_bound_cannot_overflow_scheduler_capacity() {
        let scheduler = Scheduler::new(usize::MAX);
        assert!(!scheduler.has_work());
    }
}
