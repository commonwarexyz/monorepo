//! Experimental individually allocated buffers, with relocation fused into insertion.

use super::super::pool::Pool;
use std::{
    alloc::Layout,
    marker::PhantomData,
    ptr::{self, NonNull},
    sync::Arc,
};

pub(super) struct Buffer<K, V> {
    ptr: NonNull<K>,
    pool: Option<Arc<Pool>>,
    pub(super) cap: usize,
    marker: PhantomData<V>,
}

impl<K, V> Default for Buffer<K, V> {
    fn default() -> Self {
        Self {
            ptr: NonNull::dangling(),
            pool: None,
            cap: 0,
            marker: PhantomData,
        }
    }
}

impl<K, V> Buffer<K, V> {
    pub(super) fn layout(cap: usize) -> (Layout, usize) {
        Layout::array::<K>(cap)
            .and_then(|keys| keys.extend(Layout::array::<V>(cap)?))
            .expect("partition capacity overflow")
    }

    pub(super) const fn keys(&self) -> *mut K {
        self.ptr.as_ptr()
    }

    pub(super) const fn values(&self) -> *mut V {
        if self.pool.is_none() {
            return NonNull::<V>::dangling().as_ptr();
        }
        let align = align_of::<V>();
        let offset = self
            .cap
            .wrapping_mul(size_of::<K>())
            .wrapping_add(align - 1)
            & !(align - 1);
        // SAFETY: cap was validated by layout(), and ptr owns that layout. The offset preserves
        // V's alignment and leaves room for cap values, including when V is zero-sized.
        unsafe { self.ptr.as_ptr().cast::<u8>().add(offset).cast() }
    }

    /// Relocate all cap live entries around a new entry, without a second suffix shift.
    pub(super) fn insert_full(&mut self, idx: usize, key: K, value: V, pool: &Arc<Pool>) {
        let requested = self
            .cap
            .checked_add(1)
            .expect("partition capacity overflow");
        if Self::layout(requested).0.size() == 0 {
            // SAFETY: Both types are zero-sized; their dangling pointers have the right alignment.
            // Ownership of value transfers to the caller's enlarged initialized prefix.
            unsafe {
                self.keys().write(key);
                self.values().write(value);
            }
            self.cap = requested;
            return;
        }

        let owner = self.pool.as_ref().unwrap_or(pool);
        let (allocation, cap) = owner.allocate(requested, |cap| Self::layout(cap).0);
        let (_, offset) = Self::layout(cap);
        // SAFETY: allocate returns disjoint storage matching layout(cap), with cap > old cap.
        // The caller checked idx <= old cap and all old cap entries are initialized. Copying
        // transfers ownership; neither the old buffer nor the cache drops its former contents.
        unsafe {
            let keys = allocation.as_ptr().cast::<K>();
            let values = allocation.as_ptr().add(offset).cast::<V>();
            ptr::copy_nonoverlapping(self.keys(), keys, idx);
            ptr::copy_nonoverlapping(self.keys().add(idx), keys.add(idx + 1), self.cap - idx);
            ptr::copy_nonoverlapping(self.values(), values, idx);
            ptr::copy_nonoverlapping(self.values().add(idx), values.add(idx + 1), self.cap - idx);
            keys.add(idx).write(key);
            values.add(idx).write(value);
        }

        if self.pool.is_some() {
            // SAFETY: The entries have transferred to allocation. This buffer uniquely owns ptr
            // with layout(old cap), and release retains no reference to its former contents.
            unsafe { owner.release(self.ptr.cast(), self.cap, Self::layout(self.cap).0) };
        } else {
            self.pool = Some(pool.clone());
        }
        self.ptr = allocation.cast();
        self.cap = cap;
    }
}

impl<K, V> Drop for Buffer<K, V> {
    fn drop(&mut self) {
        if let Some(pool) = &self.pool {
            // SAFETY: The owner has dropped or transferred all initialized entries. ptr is
            // exclusively owned and was allocated using layout(cap).
            unsafe { pool.release(self.ptr.cast(), self.cap, Self::layout(self.cap).0) };
        }
    }
}

// SAFETY: Moving the buffer transfers exclusive ownership of its keys and values.
unsafe impl<K: Send, V: Send> Send for Buffer<K, V> {}
// SAFETY: Shared access only exposes shared references to initialized entries.
unsafe impl<K: Sync, V: Sync> Sync for Buffer<K, V> {}

impl<K, V> Unpin for Buffer<K, V> {}
