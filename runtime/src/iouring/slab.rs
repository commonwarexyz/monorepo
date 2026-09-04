//! Owner-local generational storage shared by task and I/O registrations.
//!
//! Removal transfers ownership to the caller. No live value is replaced or
//! destroyed while manipulating slots, and exhausted generations never wrap.

use std::ops::{Index, IndexMut};

/// Slot identity checked before accessing an externally retained registration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Id {
    /// Position in the owning slab.
    pub(super) index: usize,
    /// Incarnation that distinguishes a reused slot from an old identity.
    pub(super) generation: u64,
}

/// Live ownership or a reusable vacancy in the intrusive free list.
struct Slot<T> {
    generation: u64,
    value: Option<T>,
    next_free: Option<usize>,
}

/// Growable storage accessed only by its owning worker.
pub(super) struct Slab<T> {
    slots: Vec<Slot<T>>,
    free: Option<usize>,
    len: usize,
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            free: None,
            len: 0,
        }
    }
}

impl<T> Slab<T> {
    /// Select the next identity without allocating or changing slot ownership.
    /// The caller must insert it before any other insertion on this slab.
    pub(super) fn next_id(&self) -> Id {
        self.free.map_or(
            Id {
                index: self.slots.len(),
                generation: 0,
            },
            |index| Id {
                index,
                generation: self.slots[index].generation,
            },
        )
    }

    /// Insert at a previously selected identity without replacing a live value.
    pub(super) fn insert_at(&mut self, id: Id, value: T) {
        assert_eq!(id, self.next_id());
        if id.index == self.slots.len() {
            self.slots.push(Slot {
                generation: id.generation,
                value: Some(value),
                next_free: None,
            });
        } else {
            let slot = &mut self.slots[id.index];
            assert!(slot.value.is_none());
            self.free = slot.next_free.take();
            slot.value = Some(value);
        }
        self.len += 1;
    }

    /// Construct with the selected identity using internal callback-free work.
    pub(super) fn insert_with(&mut self, make: impl FnOnce(Id) -> T) -> Id {
        let id = self.next_id();
        let value = make(id);
        self.insert_at(id, value);
        id
    }

    pub(super) fn insert(&mut self, value: T) -> Id {
        self.insert_with(|_| value)
    }

    pub(super) fn get(&self, id: Id) -> Option<&T> {
        let slot = self.slots.get(id.index)?;
        if slot.generation != id.generation {
            return None;
        }
        slot.value.as_ref()
    }

    pub(super) fn get_mut(&mut self, id: Id) -> Option<&mut T> {
        let slot = self.slots.get_mut(id.index)?;
        if slot.generation != id.generation {
            return None;
        }
        slot.value.as_mut()
    }

    /// Detach ownership and advance the generation before allowing slot reuse.
    pub(super) fn remove(&mut self, id: Id) -> Option<T> {
        let slot = self.slots.get_mut(id.index)?;
        if slot.generation != id.generation {
            return None;
        }
        let value = slot.value.take()?;
        self.len -= 1;
        if let Some(generation) = slot.generation.checked_add(1) {
            slot.generation = generation;
            slot.next_free = self.free;
            self.free = Some(id.index);
        }
        Some(value)
    }

    pub(super) const fn len(&self) -> usize {
        self.len
    }

    /// Number of allocated slots, including vacant and exhausted slots.
    pub(super) const fn slots_len(&self) -> usize {
        self.slots.len()
    }

    /// Resolve an internal index while scanning live entries during cleanup.
    pub(super) fn id_at(&self, index: usize) -> Option<Id> {
        let slot = self.slots.get(index)?;
        slot.value.as_ref().map(|_| Id {
            index,
            generation: slot.generation,
        })
    }

    /// Exercise generation exhaustion without billions of slot reuses.
    #[cfg(test)]
    pub(super) fn set_generation(&mut self, id: Id, generation: u64) -> Id {
        assert!(self.get(id).is_some());
        self.slots[id.index].generation = generation;
        Id { generation, ..id }
    }
}

// Internal FIFO links hold indices only while their target entry remains live.
impl<T> Index<usize> for Slab<T> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        self.slots[index].value.as_ref().expect("vacant slab index")
    }
}

impl<T> IndexMut<usize> for Slab<T> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        self.slots[index].value.as_mut().expect("vacant slab index")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn removal_transfers_ownership_and_rejects_stale_ids() {
        struct Owner<'a>(&'a Cell<usize>);
        impl Drop for Owner<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Cell::new(0);
        let mut slab = Slab::default();
        let first = slab.insert(Owner(&drops));
        let owner = slab.remove(first).unwrap();
        assert_eq!(drops.get(), 0);
        assert_eq!(slab.len(), 0);
        let second = slab.insert(Owner(&drops));
        assert_eq!(first.index, second.index);
        assert_ne!(first.generation, second.generation);
        assert!(slab.get(first).is_none());
        assert!(slab.get_mut(first).is_none());
        assert!(slab.remove(first).is_none());
        drop(owner);
        assert_eq!(drops.get(), 1);
        drop(slab.remove(second));
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn selected_identity_and_exhausted_generation() {
        let mut slab = Slab::default();
        let id = slab.insert_with(|id| id);
        assert_eq!(slab.get(id), Some(&id));
        let exhausted = slab.set_generation(id, u64::MAX);
        assert_eq!(slab.remove(exhausted), Some(id));
        let next = slab.next_id();
        assert_ne!(next.index, exhausted.index);
        slab.insert_at(next, next);
        assert_eq!(slab.id_at(next.index), Some(next));
        assert_eq!(slab.id_at(exhausted.index), None);
        assert_eq!(slab.len(), 1);
    }
}
