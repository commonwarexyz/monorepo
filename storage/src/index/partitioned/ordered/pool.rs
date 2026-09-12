//! Size-segregated slabs for partition buffers. An empty slab is released immediately.

use commonware_utils::sync::Mutex;
use std::{
    alloc::{Layout, alloc, dealloc, handle_alloc_error},
    collections::HashMap,
    ptr::NonNull,
    sync::{Arc, Weak},
};

// Keep slabs small enough that a few surviving buffers do not pin large allocations after
// most partitions have grown into the next size class.
const SLAB_BYTES: usize = 4 * 1024;

type Available = HashMap<(usize, usize), Vec<Weak<Slab>>>;

/// Available slabs by slot size and alignment. Weak references let empty slabs be reclaimed.
#[derive(Default)]
pub(super) struct Pool {
    available: Mutex<Available>,
}

impl Pool {
    /// Allocate an exclusively owned slot with the requested nonzero layout.
    pub(super) fn allocate(self: &Arc<Self>, layout: Layout) -> Allocation {
        assert_ne!(layout.size(), 0);
        let slot = layout.pad_to_align();
        let key = (slot.size(), slot.align());
        let mut available = self.available.lock();
        let slabs = available.entry(key).or_default();
        while let Some(weak) = slabs.last() {
            let Some(slab) = weak.upgrade() else {
                slabs.pop();
                continue;
            };
            let mut free = slab.free.lock();
            let offset = free.pop().expect("available slab has a free slot");
            if free.is_empty() {
                slabs.pop();
            }
            drop(free);
            // SAFETY: offset is a free, aligned slot wholly within the slab allocation.
            let ptr = unsafe { NonNull::new_unchecked(slab.ptr.as_ptr().add(offset)) };
            return Allocation { ptr, slab };
        }

        let count = (SLAB_BYTES / slot.size()).max(1);
        let layout = Layout::from_size_align(slot.size() * count, slot.align()).unwrap();
        // SAFETY: layout is nonzero and valid.
        let raw = unsafe { alloc(layout) };
        let Some(ptr) = NonNull::new(raw) else {
            handle_alloc_error(layout);
        };
        let slab = Arc::new(Slab {
            ptr,
            layout,
            slot,
            free: Mutex::new((1..count).rev().map(|i| i * slot.size()).collect()),
            pool: self.clone(),
        });
        if count > 1 {
            slabs.push(Arc::downgrade(&slab));
        }
        Allocation { ptr, slab }
    }
}

/// Raw storage shared by disjoint slots. Each live slot keeps the slab and its pool alive.
pub(super) struct Slab {
    ptr: NonNull<u8>,
    layout: Layout,
    slot: Layout,
    free: Mutex<Vec<usize>>,
    pub(super) pool: Arc<Pool>,
}

impl Drop for Slab {
    fn drop(&mut self) {
        // SAFETY: Every live allocation holds a strong reference to the slab, so no slots remain
        // in use. This is the layout with which ptr was allocated.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

// SAFETY: Slot ownership is exclusive and free-slot bookkeeping is protected by a mutex.
unsafe impl Send for Slab {}
// SAFETY: Shared access never exposes the backing bytes; only disjoint owned slots expose them.
unsafe impl Sync for Slab {}

/// An owned, uninitialized slot. Its owner must drop any stored values before releasing it.
pub(super) struct Allocation {
    pub(super) ptr: NonNull<u8>,
    pub(super) slab: Arc<Slab>,
}

impl Drop for Allocation {
    fn drop(&mut self) {
        // A single-slot slab cannot be reused; dropping its Arc releases the slab directly.
        if self.slab.layout.size() == self.slab.slot.size() {
            return;
        }
        // SAFETY: ptr addresses a slot within this slab's allocation.
        let offset = unsafe { self.ptr.as_ptr().offset_from(self.slab.ptr.as_ptr()) } as usize;
        let was_full = {
            let mut free = self.slab.free.lock();
            let was_full = free.is_empty();
            free.push(offset);
            was_full
        };
        if was_full {
            // Release the slab lock before taking the pool lock: allocation takes them in the
            // opposite order. Only the first return to a full slab queues it as available.
            self.slab
                .pool
                .available
                .lock()
                .entry((self.slab.slot.size(), self.slab.slot.align()))
                .or_default()
                .push(Arc::downgrade(&self.slab));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reuse_and_release() {
        let pool = Arc::new(Pool::default());
        let layout = Layout::from_size_align(1024, 8).unwrap();
        let mut allocations: Vec<_> = (0..4).map(|_| pool.allocate(layout)).collect();
        let slab = Arc::downgrade(&allocations[0].slab);
        assert!(
            allocations
                .iter()
                .all(|a| Arc::ptr_eq(&a.slab, &allocations[0].slab))
        );
        let ptr = allocations[0].ptr;
        drop(allocations.remove(0));
        let reused = pool.allocate(layout);
        assert_eq!(reused.ptr, ptr);
        drop(allocations);
        assert!(slab.upgrade().is_some());
        drop(reused);
        assert!(slab.upgrade().is_none());
        let allocation = pool.allocate(layout);
        assert_eq!(allocation.ptr.as_ptr().align_offset(layout.align()), 0);
    }

    #[test]
    fn test_dedicated_slabs_leave_no_available_entries() {
        for size in [SLAB_BYTES / 2 + 8, SLAB_BYTES, SLAB_BYTES * 2] {
            let pool = Arc::new(Pool::default());
            let layout = Layout::from_size_align(size, 8).unwrap();
            let allocations: Vec<_> = (0..64).map(|_| pool.allocate(layout)).collect();
            let slab = Arc::downgrade(&allocations[0].slab);

            // Release the whole batch without allocating again to sweep dead weak references.
            drop(allocations);
            assert!(slab.upgrade().is_none());
            assert_eq!(
                pool.available.lock().values().map(Vec::len).sum::<usize>(),
                0
            );
        }
    }

    #[test]
    fn test_pool_lives_with_allocations() {
        let pool = Arc::new(Pool::default());
        let weak = Arc::downgrade(&pool);
        let allocation = pool.allocate(Layout::new::<u64>());
        drop(pool);
        assert!(weak.upgrade().is_some());
        drop(allocation);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn test_concurrent_allocation() {
        let pool = Arc::new(Pool::default());
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let pool = &pool;
                scope.spawn(move || {
                    for i in 0..100 {
                        let allocation = pool.allocate(Layout::new::<[u64; 128]>());
                        // SAFETY: This slot has sufficient space and alignment and is exclusively
                        // owned by this thread. Other threads must receive disjoint slots.
                        unsafe {
                            allocation.ptr.as_ptr().cast::<[u64; 128]>().write([i; 128]);
                            std::thread::yield_now();
                            assert_eq!(*allocation.ptr.as_ptr().cast::<[u64; 128]>(), [i; 128]);
                        }
                    }
                });
            }
        });
    }
}
