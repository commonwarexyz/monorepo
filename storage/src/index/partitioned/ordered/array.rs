//! Parallel key/value arrays sharing one slab slot, length, and capacity.
//!
//! Keys precede values, with padding only between the arrays. This avoids per-entry padding and
//! two independently growing allocations per partition. Only the first `len` entries are live.

#[cfg_attr(
    any(index_alloc = "exact", index_alloc = "reuse"),
    path = "buffer_exact.rs"
)]
#[cfg_attr(
    not(any(index_alloc = "exact", index_alloc = "reuse")),
    path = "buffer.rs"
)]
mod buffer;

use super::pool::Pool;
use buffer::Buffer;
use std::{ops::Range, ptr, slice, sync::Arc};

/// Parallel arrays with a shared length. Keys are Copy; values may own resources.
pub(super) struct Entries<K: Copy, V> {
    buffer: Buffer<K, V>,
    len: usize,
}

impl<K: Copy, V> Default for Entries<K, V> {
    fn default() -> Self {
        Self {
            buffer: Buffer::default(),
            len: 0,
        }
    }
}

impl<K: Copy, V> Entries<K, V> {
    pub(super) const fn len(&self) -> usize {
        self.len
    }

    pub(super) const fn keys(&self) -> &[K] {
        // SAFETY: The first len keys are initialized, aligned, and borrowed from self.
        unsafe { slice::from_raw_parts(self.buffer.keys(), self.len) }
    }

    pub(super) const fn values(&self) -> &[V] {
        // SAFETY: The first len values are initialized, aligned, and borrowed from self.
        unsafe { slice::from_raw_parts(self.buffer.values(), self.len) }
    }

    pub(super) const fn values_mut(&mut self) -> &mut [V] {
        // SAFETY: The first len values are initialized and aligned; self is exclusively borrowed.
        unsafe { slice::from_raw_parts_mut(self.buffer.values(), self.len) }
    }

    pub(super) fn insert(&mut self, idx: usize, key: K, value: V, pool: &Arc<Pool>) {
        assert!(idx <= self.len, "partition insertion out of bounds");
        if self.len == self.buffer.cap {
            cfg_if::cfg_if! {
                if #[cfg(any(index_alloc = "exact", index_alloc = "reuse"))] {
                    self.buffer.insert_full(idx, key, value, pool);
                    self.len += 1;
                    return;
                } else {
                    self.buffer.grow(pool);
                }
            }
        }
        // SAFETY: idx <= len < cap. Shift initialized entries within each array (possibly
        // overlapping), then initialize the gap. No reference survives growth or the moves.
        unsafe {
            let keys = self.buffer.keys();
            let values = self.buffer.values();
            ptr::copy(keys.add(idx), keys.add(idx + 1), self.len - idx);
            ptr::copy(values.add(idx), values.add(idx + 1), self.len - idx);
            keys.add(idx).write(key);
            values.add(idx).write(value);
        }
        self.len += 1;
    }

    pub(super) fn remove(&mut self, idx: usize) -> V {
        assert!(idx < self.len, "partition removal out of bounds");
        // SAFETY: idx is initialized. Transfer ownership of its value to the caller and shift
        // the tail into the gap. The duplicate last entry is excluded by reducing len below.
        let value = unsafe {
            let keys = self.buffer.keys();
            let values = self.buffer.values();
            let value = values.add(idx).read();
            ptr::copy(keys.add(idx + 1), keys.add(idx), self.len - idx - 1);
            ptr::copy(values.add(idx + 1), values.add(idx), self.len - idx - 1);
            value
        };
        self.len -= 1;
        self.release_empty();
        value
    }

    pub(super) fn remove_range(&mut self, range: Range<usize>) {
        assert!(range.start <= range.end && range.end <= self.len);
        let count = range.len();
        if count == 0 {
            return;
        }
        // Move removed values to the tail before dropping them, so even a panicking destructor
        // leaves an initialized, aligned prefix of keys and values.
        self.values_mut()[range.start..].rotate_left(count);
        // SAFETY: The range was checked; the live key tail fits at range.start and may overlap.
        unsafe {
            let keys = self.buffer.keys();
            ptr::copy(
                keys.add(range.end),
                keys.add(range.start),
                self.len - range.end,
            );
        }
        self.len -= count;
        // SAFETY: The removed values now occupy the initialized tail, excluded from len so
        // unwinding cannot drop them twice. Slice drop also drops remaining values on unwind.
        unsafe {
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(
                self.buffer.values().add(self.len),
                count,
            ));
        }
        self.release_empty();
    }

    fn release_empty(&mut self) {
        if self.len == 0 {
            self.buffer = Buffer::default();
        }
    }

    pub(super) fn into_vecs(mut self) -> (Vec<K>, Vec<V>) {
        let keys = self.keys().to_vec();
        let mut values = Vec::with_capacity(self.len);
        // SAFETY: The destination has space for len values, the source is initialized, and the
        // allocations do not overlap. Transfer ownership by setting the lengths after the copy.
        unsafe {
            ptr::copy_nonoverlapping(self.buffer.values(), values.as_mut_ptr(), self.len);
            values.set_len(self.len);
        }
        self.len = 0;
        (keys, values)
    }
}

impl<K: Copy, V> Drop for Entries<K, V> {
    fn drop(&mut self) {
        // SAFETY: Exactly the first len values are live. Buffer's field destructor releases the
        // slot afterwards, including when a value destructor panics. Keys are Copy.
        unsafe {
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(
                self.buffer.values(),
                self.len,
            ))
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::test_rng;
    use rand::RngExt;
    use std::{
        cell::Cell,
        marker::PhantomPinned,
        panic::{AssertUnwindSafe, catch_unwind},
        rc::Rc,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn test_auto_traits() {
        fn check<T: Send + Sync + Unpin>() {}
        check::<Entries<[u8; 5], PhantomPinned>>();
        check::<super::super::Index<crate::translator::Cap<5>, PhantomPinned, 3>>();
    }

    #[test]
    fn test_memory_budget_and_release() {
        let mut entries = Entries::<[u8; 5], u64>::default();
        assert_eq!(
            Buffer::<[u8; 5], u64>::layout(entries.buffer.cap).0.size(),
            0
        );
        for i in 0..256 {
            entries.insert(i, [0; 5], i as u64, &Arc::default());
            let bytes = Buffer::<[u8; 5], u64>::layout(entries.buffer.cap).0.size();
            // Geometric growth, plus padding between the two arrays.
            assert!(bytes <= entries.len().max(2) * 13 * 2 + 7);
        }
        entries.remove_range(0..256);
        assert_eq!(entries.buffer.cap, 0);
        entries.insert(0, [1; 5], 7, &Arc::default());
        assert_eq!(entries.remove(0), 7);
        assert_eq!(entries.buffer.cap, 0);
    }

    #[test]
    fn test_operations_match_vecs() {
        let mut rng = test_rng();
        let mut entries = Entries::<[u8; 5], Box<u64>>::default();
        let mut keys = Vec::new();
        let mut values = Vec::new();
        for _ in 0..1000 {
            match rng.random_range(0..5) {
                0..=1 => {
                    let idx = rng.random_range(0..=keys.len());
                    let key = rng.random();
                    let value = rng.random();
                    keys.insert(idx, key);
                    values.insert(idx, Box::new(value));
                    entries.insert(idx, key, Box::new(value), &Arc::default());
                }
                2 if !keys.is_empty() => {
                    let idx = rng.random_range(0..keys.len());
                    keys.remove(idx);
                    assert_eq!(entries.remove(idx), values.remove(idx));
                }
                3 => {
                    let start = rng.random_range(0..=keys.len());
                    let end = rng.random_range(start..=keys.len());
                    keys.drain(start..end);
                    values.drain(start..end);
                    entries.remove_range(start..end);
                }
                4 if !keys.is_empty() => {
                    let idx = rng.random_range(0..keys.len());
                    let value = rng.random();
                    *values[idx] = value;
                    *entries.values_mut()[idx] = value;
                }
                _ => {}
            }
            assert_eq!(entries.keys(), keys);
            assert_eq!(entries.values(), values);
        }
        assert_eq!(entries.into_vecs(), (keys, values));
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(align(64))]
    struct Aligned(u64);

    fn check_types<K: Copy + Eq + std::fmt::Debug, V: Clone + Eq + std::fmt::Debug>(
        key: K,
        value: V,
    ) {
        let mut entries = Entries::default();
        assert!(entries.keys().is_empty());
        assert!(entries.values().is_empty());
        // Cross every growth boundary up to and beyond the production spill threshold. A cursor
        // can keep adding collisions past that threshold before the index regains control.
        for i in 0..600 {
            entries.insert(i / 2, key, value.clone(), &Arc::default());
            assert_eq!(entries.keys()[i / 2], key);
            assert_eq!(entries.values()[i / 2], value);
        }
        assert_eq!(entries.keys(), vec![key; 600]);
        assert_eq!(entries.values(), vec![value.clone(); 600]);
        entries.remove_range(100..500);
        assert_eq!(entries.remove(0), value);
        let (keys, values) = entries.into_vecs();
        assert_eq!(keys, vec![key; 199]);
        assert_eq!(values, vec![value; 199]);
    }

    #[test]
    fn test_alignment_and_zero_sized_types() {
        check_types([1; 5], Aligned(2));
        check_types(Aligned(3), [4u8; 5]);
        check_types((), Aligned(5));
        check_types(Aligned(6), ());
        check_types((), ());
    }

    struct Tracked {
        drops: Rc<Cell<usize>>,
        panic: bool,
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
            assert!(!self.panic, "value drop panic");
        }
    }

    #[test]
    fn test_value_ownership() {
        let drops = Rc::new(Cell::new(0));
        let value = || Tracked {
            drops: drops.clone(),
            panic: false,
        };
        let mut entries = Entries::default();
        for i in 0..100 {
            entries.insert(i, i, value(), &Arc::default());
        }
        drop(entries.remove(10));
        entries.remove_range(10..20);
        entries.values_mut()[0] = value();
        assert_eq!(drops.get(), 12);
        let (_, values) = entries.into_vecs();
        assert_eq!(drops.get(), 12);
        drop(values);
        assert_eq!(drops.get(), 101);
    }

    #[test]
    fn test_panicking_destructor() {
        for range in [0..4, 1..3] {
            let drops = Rc::new(Cell::new(0));
            let mut entries = Entries::default();
            for i in 0..4 {
                entries.insert(
                    i,
                    i,
                    Tracked {
                        drops: drops.clone(),
                        panic: i == 1,
                    },
                    &Arc::default(),
                );
            }
            assert!(
                catch_unwind(AssertUnwindSafe(|| entries.remove_range(range.clone()))).is_err()
            );
            assert_eq!(drops.get(), range.len());
            if range == (1..3) {
                assert_eq!(entries.keys(), &[0, 3]);
            } else {
                assert_eq!(entries.len(), 0);
            }
            drop(entries);
            assert_eq!(drops.get(), 4);
        }
        let drops = Rc::new(Cell::new(0));
        let mut entries = Entries::default();
        entries.insert(
            0,
            (),
            Tracked {
                drops: drops.clone(),
                panic: true,
            },
            &Arc::default(),
        );
        assert!(catch_unwind(AssertUnwindSafe(|| drop(entries))).is_err());
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn test_zero_sized_destructors() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        #[repr(align(64))]
        struct ZeroSized;
        impl Drop for ZeroSized {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut entries = Entries::default();
        for i in 0..100 {
            entries.insert(i, (), ZeroSized, &Arc::default());
        }
        drop(entries.remove(0));
        entries.remove_range(10..20);
        let (_, values) = entries.into_vecs();
        drop(values);
        assert_eq!(DROPS.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn test_capacity_overflow() {
        assert!(catch_unwind(|| Buffer::<[u8; 5], u64>::layout(usize::MAX)).is_err());
        assert!(catch_unwind(|| Buffer::<[u8; 5], u64>::layout(isize::MAX as usize / 8)).is_err());
        let mut entries = Entries::<(), ()>::default();
        entries.len = usize::MAX;
        entries.buffer.cap = usize::MAX;
        assert!(
            catch_unwind(AssertUnwindSafe(|| entries.insert(
                0,
                (),
                (),
                &Arc::default()
            )))
            .is_err()
        );
        entries.len = 0;
    }
}
