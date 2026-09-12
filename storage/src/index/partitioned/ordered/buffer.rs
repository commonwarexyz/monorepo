//! Partition storage backed by a pooled slab slot.

use super::super::pool::{Allocation, Pool};
use std::{
    alloc::Layout,
    marker::PhantomData,
    num::NonZeroUsize,
    ptr::{self, NonNull},
    sync::Arc,
};

/// A slab slot containing space for `cap` keys followed by `cap` values.
pub(super) struct Buffer<K, V> {
    allocation: Option<Allocation>,
    pub(super) cap: usize,
    marker: PhantomData<(K, V)>,
}

impl<K, V> Default for Buffer<K, V> {
    fn default() -> Self {
        Self {
            allocation: None,
            cap: 0,
            marker: PhantomData,
        }
    }
}

impl<K, V> Buffer<K, V> {
    /// Combined layout and the offset of the values. Layout checks all size arithmetic.
    pub(super) fn layout(cap: usize) -> (Layout, usize) {
        Layout::array::<K>(cap)
            .and_then(|keys| keys.extend(Layout::array::<V>(cap)?))
            .expect("partition capacity overflow")
    }

    pub(super) const fn keys(&self) -> *mut K {
        match &self.allocation {
            Some(allocation) => allocation.ptr.as_ptr().cast(),
            None => NonNull::<K>::dangling().as_ptr(),
        }
    }

    pub(super) const fn values(&self) -> *mut V {
        // Capacity was validated by layout() on growth. Wrapping arithmetic avoids repeating
        // overflow checks on every lookup; these operations cannot wrap for a valid buffer.
        let align = align_of::<V>();
        let offset = self
            .cap
            .wrapping_mul(size_of::<K>())
            .wrapping_add(align - 1)
            & !(align - 1);
        // SAFETY: The offset is within the allocation (or zero for an empty/ZST buffer),
        // and the layout and dangling pointer both satisfy V's alignment.
        unsafe {
            match &self.allocation {
                Some(allocation) => allocation.ptr.as_ptr().add(offset).cast(),
                None => NonNull::<V>::dangling().as_ptr(),
            }
        }
    }

    /// Grow a full buffer, preserving all `cap` initialized entries in both arrays.
    pub(super) fn grow(&mut self, pool: &Arc<Pool>) {
        let (old_layout, _) = Self::layout(self.cap);
        let cap = if let Some(entry_size) = NonZeroUsize::new(size_of::<K>() + size_of::<V>()) {
            // Use the capacity available in a power-of-two byte budget, including space that
            // would otherwise be lost to allocator size-class rounding.
            let bytes = old_layout
                .size()
                .checked_next_power_of_two()
                .and_then(|bytes| bytes.checked_mul(2))
                .expect("partition capacity overflow")
                .max(64)
                .max(Self::layout(1).0.size().next_power_of_two());
            // bytes and each value's size are multiples of V's alignment, so inter-array padding
            // still fits within the byte budget.
            (bytes / entry_size).max(1)
        } else {
            self.cap
                .checked_add(1)
                .expect("partition capacity overflow")
        };
        let (layout, offset) = Self::layout(cap);
        if layout.size() != 0 {
            let pool = self.allocation.as_ref().map_or(pool, |a| &a.slab.pool);
            let allocation = pool.allocate(layout);
            // SAFETY: The new slot is disjoint from the old one, fits both arrays, and preserves
            // their alignment. Transfer all initialized entries before releasing the old slot.
            unsafe {
                ptr::copy_nonoverlapping(self.keys(), allocation.ptr.as_ptr().cast(), self.cap);
                ptr::copy_nonoverlapping(
                    self.values(),
                    allocation.ptr.as_ptr().add(offset).cast(),
                    self.cap,
                );
            }
            self.allocation = Some(allocation);
        }
        self.cap = cap;
    }
}

// SAFETY: The slot is uniquely owned; moving it transfers ownership of its keys and values.
unsafe impl<K: Send, V: Send> Send for Buffer<K, V> {}
// SAFETY: Shared access only exposes shared references to initialized keys and values.
unsafe impl<K: Sync, V: Sync> Sync for Buffer<K, V> {}

// Moving the buffer does not move its heap-allocated entries.
impl<K, V> Unpin for Buffer<K, V> {}
