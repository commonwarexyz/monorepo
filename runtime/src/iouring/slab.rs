//! Generational slot storage for a worker's local registrations.
//!
//! Removal returns values so callers can drop them outside worker borrows.
//! Slots with exhausted generations are permanently retired.

/// Generational handle to a slot. A handle stops resolving once its slot is removed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Id {
    /// Position in the owning slab.
    pub index: u32,
    /// Incarnation that distinguishes a reused slot from an old identity.
    pub generation: u64,
}

/// One slot and its current incarnation.
struct Slot<T> {
    /// Generation checked when accessing a slot by [`Id`].
    generation: u64,
    /// Held value, or `None` while the slot is vacant or retired.
    value: Option<T>,
    /// Next vacant slot in the free list, meaningful only while this slot is vacant.
    next_free: Option<usize>,
}

/// Growable storage accessed only by its owning worker.
pub struct Slab<T> {
    /// Every slot ever allocated, live or not.
    slots: Vec<Slot<T>>,
    /// Head of the intrusive free list, most recently vacated first.
    free: Option<usize>,
    /// Number of live values.
    len: usize,
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl<T> Slab<T> {
    /// Create an empty slab with room for at least `capacity` slots.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            slots: Vec::with_capacity(capacity),
            free: None,
            len: 0,
        }
    }

    /// Insert a value built from its own identity.
    ///
    /// The value is constructed before the slab changes, so a panicking
    /// constructor leaves the slab untouched.
    pub fn insert_with(&mut self, make: impl FnOnce(Id) -> T) -> Id {
        let index = self.free.unwrap_or(self.slots.len());
        let generation = self.slots.get(index).map_or(0, |slot| slot.generation);
        let id = Id {
            index: u32::try_from(index).expect("slab slot index overflow"),
            generation,
        };
        let value = make(id);

        if index == self.slots.len() {
            self.slots.push(Slot {
                generation,
                value: Some(value),
                next_free: None,
            });
        } else {
            let slot = &mut self.slots[index];
            assert!(slot.value.is_none());
            self.free = slot.next_free.take();
            slot.value = Some(value);
        }

        self.len += 1;
        id
    }

    /// Insert a value and return its identity.
    pub fn insert(&mut self, value: T) -> Id {
        self.insert_with(|_| value)
    }

    /// Borrow the live value at `id`, if any.
    pub fn get(&self, id: Id) -> Option<&T> {
        let slot = self.slots.get(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        slot.value.as_ref()
    }

    /// Mutably borrow the live value at `id`, if any.
    pub fn get_mut(&mut self, id: Id) -> Option<&mut T> {
        let slot = self.slots.get_mut(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        slot.value.as_mut()
    }

    /// Remove a live value, advancing the slot's generation so `id` stops resolving.
    pub fn remove(&mut self, id: Id) -> Option<T> {
        let slot = self.slots.get_mut(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        let value = slot.value.take()?;
        self.len -= 1;
        if let Some(generation) = slot.generation.checked_add(1) {
            slot.generation = generation;
            slot.next_free = self.free;
            self.free = Some(id.index as usize);
        }
        Some(value)
    }

    /// Number of live values.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Number of slots, including vacant and retired ones.
    pub const fn slots(&self) -> usize {
        self.slots.len()
    }

    /// Identity of the live entry at `index`, if any.
    pub fn id_at(&self, index: usize) -> Option<Id> {
        let slot = self.slots.get(index)?;
        slot.value.as_ref().map(|_| Id {
            index: u32::try_from(index).expect("slab slot index overflow"),
            generation: slot.generation,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// Force a live slot's generation so tests can reach exhaustion.
    pub fn set_generation<T>(slab: &mut Slab<T>, id: Id, generation: u64) -> Id {
        assert!(slab.get(id).is_some());
        slab.slots[id.index as usize].generation = generation;
        Id { generation, ..id }
    }

    #[test]
    fn test_insert_access_and_remove() {
        let mut slab = Slab::default();
        assert_eq!(slab.len(), 0);
        assert_eq!(slab.slots(), 0);
        assert_eq!(slab.id_at(0), None);

        let first = slab.insert(10);
        let second = slab.insert(20);

        assert_ne!(first.index, second.index);
        assert_eq!(slab.len(), 2);
        assert_eq!(slab.slots(), 2);
        assert_eq!(slab.get(first), Some(&10));
        assert_eq!(slab.id_at(first.index as usize), Some(first));
        assert_eq!(slab.id_at(second.index as usize), Some(second));

        *slab.get_mut(first).unwrap() = 11;
        assert_eq!(slab.get(first), Some(&11));
        assert_eq!(slab.get(second), Some(&20));

        // Removing a value leaves its slot available for subsequent reuse.
        assert_eq!(slab.remove(first), Some(11));
        assert_eq!(slab.len(), 1);
        assert_eq!(slab.slots(), 2);
        assert_eq!(slab.id_at(first.index as usize), None);
        assert_eq!(slab.id_at(second.index as usize), Some(second));

        assert_eq!(slab.remove(second), Some(20));
        assert_eq!(slab.len(), 0);
        assert_eq!(slab.slots(), 2);
    }

    #[test]
    fn test_invalid_ids_leave_entries_unchanged() {
        let mut slab = Slab::default();
        let removed = slab.insert(10);
        let live = slab.insert(20);
        assert_eq!(slab.remove(removed), Some(10));

        // Reject stale, vacant, mismatched, and out-of-bounds identities.
        for id in [
            removed,
            Id {
                generation: removed.generation + 1,
                ..removed
            },
            Id {
                generation: live.generation + 1,
                ..live
            },
            Id {
                index: slab.slots() as u32,
                generation: 0,
            },
            Id {
                index: u32::MAX,
                generation: u64::MAX,
            },
        ] {
            assert!(slab.get(id).is_none(), "{id:?}");
            assert!(slab.get_mut(id).is_none(), "{id:?}");
            assert!(slab.remove(id).is_none(), "{id:?}");
        }

        assert_eq!(slab.len(), 1);
        assert_eq!(slab.slots(), 2);
        assert_eq!(slab.get(live), Some(&20));
        assert_eq!(slab.id_at(removed.index as usize), None);
        assert_eq!(slab.id_at(slab.slots()), None);
        assert_eq!(slab.id_at(usize::MAX), None);

        // Rejected removals must not lose or duplicate a free-list entry.
        let reused = slab.insert(30);
        let appended = slab.insert(40);

        assert_eq!(reused.index, removed.index);
        assert_eq!(appended.index, 2);
        assert_eq!(slab.get(reused), Some(&30));
        assert_eq!(slab.len(), 3);
        assert_eq!(slab.slots(), 3);
    }

    #[test]
    fn test_reuse_preserves_live_entries_and_rejects_stale_ids() {
        let mut slab = Slab::default();
        let first = slab.insert_with(|id| id);
        let middle = slab.insert_with(|id| id);
        let last = slab.insert_with(|id| id);

        assert_eq!(slab.get(first), Some(&first));
        assert_eq!(slab.remove(first), Some(first));
        assert_eq!(slab.remove(last), Some(last));

        // Reuse vacancies in reverse removal order, passing the new ID to each constructor.
        let reused_last = slab.insert_with(|id| id);
        let reused_first = slab.insert_with(|id| id);

        for (old, current) in [(last, reused_last), (first, reused_first)] {
            assert_eq!(current.index, old.index);
            assert_eq!(current.generation, old.generation + 1);
            assert_eq!(slab.get(current), Some(&current));
            assert_eq!(slab.id_at(current.index as usize), Some(current));
            assert!(slab.get(old).is_none());
            assert!(slab.get_mut(old).is_none());
            assert!(slab.remove(old).is_none());
        }

        assert_eq!(slab.get(middle), Some(&middle));
        assert_eq!(slab.len(), 3);
        assert_eq!(slab.slots(), 3);
    }

    #[test]
    fn test_exhausted_generation_retires_slot() {
        let mut slab = Slab::default();
        let id = slab.insert(10);
        let penultimate = set_generation(&mut slab, id, u64::MAX - 1);

        // The maximum generation remains usable for one final insertion.
        assert_eq!(slab.remove(penultimate), Some(10));
        let exhausted = slab.insert(20);
        assert_eq!(exhausted.index, id.index);
        assert_eq!(exhausted.generation, u64::MAX);

        // Retiring a slot must preserve any other reusable slots.
        let other = slab.insert(30);
        assert_eq!(slab.remove(other), Some(30));
        assert_eq!(slab.remove(exhausted), Some(20));

        assert_eq!(slab.len(), 0);
        assert_eq!(slab.slots(), 2);
        assert_eq!(slab.id_at(exhausted.index as usize), None);
        assert!(slab.get(exhausted).is_none());
        assert!(slab.get_mut(exhausted).is_none());
        assert!(slab.remove(exhausted).is_none());

        let reused = slab.insert(40);
        let appended = slab.insert(50);

        assert_eq!(reused.index, other.index);
        assert_eq!(appended.index, 2);
        assert_eq!(slab.len(), 2);
        assert_eq!(slab.slots(), 3);
    }

    #[test]
    fn test_constructor_panic_leaves_slab_unchanged() {
        // Exercise both appending a new slot and reusing a vacant one.
        for reuse in [false, true] {
            let mut slab = Slab::default();
            let live = slab.insert(10);
            if reuse {
                let vacant = slab.insert(20);
                slab.remove(vacant).unwrap();
            }

            let slots = slab.slots();
            let mut selected = None;
            let result = catch_unwind(AssertUnwindSafe(|| {
                slab.insert_with(|id| {
                    selected = Some(id);
                    panic!("constructor");
                });
            }));

            assert!(result.is_err());
            assert_eq!(slab.len(), 1);
            assert_eq!(slab.slots(), slots);
            assert_eq!(slab.get(live), Some(&10));

            // The failed constructor must not consume the selected slot or generation.
            let next = slab.insert(30);
            assert_eq!(Some(next), selected);
            assert_eq!(slab.get(next), Some(&30));
            assert_eq!(slab.len(), 2);
            assert_eq!(slab.slots(), 2);
        }
    }
}
