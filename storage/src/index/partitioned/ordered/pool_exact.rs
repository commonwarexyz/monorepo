//! Experimental individual allocations with an optional bounded cache of empty buffers.

#[cfg(index_alloc = "reuse")]
use commonware_utils::sync::Mutex;
use std::{
    alloc::{Layout, alloc, dealloc, handle_alloc_error},
    ptr::NonNull,
};

#[cfg_attr(not(index_alloc = "reuse"), derive(Default))]
pub(super) struct Pool {
    #[cfg(index_alloc = "reuse")]
    cache: Mutex<cache::Cache>,
    #[cfg(index_alloc = "reuse")]
    report: bool,
}

#[cfg(index_alloc = "reuse")]
impl Default for Pool {
    fn default() -> Self {
        Self {
            #[cfg(index_alloc = "reuse")]
            cache: Mutex::new(cache::Cache::new(
                std::env::var("INDEX_BUFFER_CACHE_BYTES")
                    .map(|bytes| bytes.parse().expect("invalid INDEX_BUFFER_CACHE_BYTES"))
                    .unwrap_or(1024 * 1024),
            )),
            #[cfg(index_alloc = "reuse")]
            report: std::env::var_os("INDEX_BUFFER_CACHE_STATS").is_some(),
        }
    }
}

impl Pool {
    /// Return storage for the requested capacity, or a slightly larger compatible cached buffer.
    pub(super) fn allocate(
        &self,
        cap: usize,
        layout: impl Fn(usize) -> Layout,
    ) -> (NonNull<u8>, usize) {
        #[cfg(index_alloc = "reuse")]
        if let Some(found) = self.cache.lock().take(cap, &layout) {
            return found;
        }
        let layout = layout(cap);
        assert_ne!(layout.size(), 0);
        // SAFETY: layout is valid and nonzero. The returned storage is exclusively owned.
        let ptr = unsafe { alloc(layout) };
        (
            NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout)),
            cap,
        )
    }

    /// # Safety
    /// ptr must be an exclusively owned allocation with this layout, with no live contents.
    pub(super) unsafe fn release(&self, ptr: NonNull<u8>, _cap: usize, layout: Layout) {
        #[cfg(index_alloc = "reuse")]
        // SAFETY: The caller transfers an empty, exclusively owned allocation with this layout.
        if unsafe { self.cache.lock().put(ptr, _cap, layout) } {
            return;
        }
        // SAFETY: The cache did not take ownership. The caller supplied the allocation's layout.
        unsafe { dealloc(ptr.as_ptr(), layout) };
    }
}

#[cfg(index_alloc = "reuse")]
impl Drop for Pool {
    fn drop(&mut self) {
        if self.report {
            let cache = self.cache.get_mut();
            eprintln!(
                "buffer_cache: hits={} misses={} evicted={} peak_bytes={} cached_bytes={} budget={}",
                cache.hits,
                cache.misses,
                cache.evicted,
                cache.peak_bytes,
                cache.bytes,
                cache.budget,
            );
        }
    }
}

#[cfg(index_alloc = "reuse")]
mod cache {
    use super::*;

    // Cursor overshoot is allowed, but does not grow the cache's metadata or search range.
    const MAX_CAP: usize = 512;
    const MAX_EXTRA: usize = 4;

    struct Bin {
        head: Option<NonNull<u8>>,
        layout: Layout,
        last_used: u64,
    }

    impl Default for Bin {
        fn default() -> Self {
            Self {
                head: None,
                layout: Layout::new::<()>(),
                last_used: 0,
            }
        }
    }

    impl Bin {
        fn pop(&mut self) -> Option<NonNull<u8>> {
            let ptr = self.head?;
            // SAFETY: put initialized the link in this exclusively owned empty allocation.
            // Unaligned access also supports packed key/value layouts with byte alignment.
            self.head = unsafe { ptr.as_ptr().cast::<Option<NonNull<u8>>>().read_unaligned() };
            Some(ptr)
        }
    }

    pub(super) struct Cache {
        bins: Box<[Bin]>,
        clock: u64,
        pub(super) budget: usize,
        pub(super) bytes: usize,
        pub(super) peak_bytes: usize,
        pub(super) hits: u64,
        pub(super) misses: u64,
        pub(super) evicted: u64,
    }

    impl Cache {
        pub(super) fn new(budget: usize) -> Self {
            Self {
                bins: Box::default(),
                clock: 0,
                budget,
                bytes: 0,
                peak_bytes: 0,
                hits: 0,
                misses: 0,
                evicted: 0,
            }
        }

        pub(super) fn take(
            &mut self,
            cap: usize,
            layout: &impl Fn(usize) -> Layout,
        ) -> Option<(NonNull<u8>, usize)> {
            self.clock = self.clock.saturating_add(1);
            if self.bins.is_empty() {
                self.misses = self.misses.saturating_add(1);
                return None;
            }
            if let Some(bin) = self.bins.get_mut(cap) {
                bin.last_used = self.clock;
            }
            for capacity in cap..=cap.saturating_add(MAX_EXTRA).min(MAX_CAP) {
                let bin = &mut self.bins[capacity];
                // Checking the full layout permits sharing a pool without assuming a key/value
                // type: matching capacity alone is insufficient for safe reuse.
                if bin.head.is_some() && bin.layout == layout(capacity) {
                    let ptr = bin.pop().unwrap();
                    bin.last_used = self.clock;
                    self.bytes -= bin.layout.size();
                    self.hits = self.hits.saturating_add(1);
                    return Some((ptr, capacity));
                }
            }
            self.misses = self.misses.saturating_add(1);
            None
        }

        /// # Safety
        /// ptr must own empty storage with layout. true transfers its ownership into this cache.
        pub(super) unsafe fn put(&mut self, ptr: NonNull<u8>, cap: usize, layout: Layout) -> bool {
            if cap == 0
                || cap > MAX_CAP
                || layout.size() < size_of::<Option<NonNull<u8>>>()
                || layout.size() > self.budget
            {
                return false;
            }
            if self.bins.is_empty() {
                self.bins = (0..=MAX_CAP).map(|_| Bin::default()).collect();
            }
            if self.bins[cap].head.is_some() && self.bins[cap].layout != layout {
                return false;
            }
            while self.bytes > self.budget - layout.size() {
                // Evict a whole cold size at once, amortizing the bounded scan over its buffers.
                let cold = self
                    .bins
                    .iter()
                    .enumerate()
                    .filter(|(_, bin)| bin.head.is_some())
                    .min_by_key(|(_, bin)| bin.last_used)
                    .map(|(i, _)| i)
                    .expect("cached bytes belong to a nonempty bin");
                let bin = &mut self.bins[cold];
                while let Some(ptr) = bin.pop() {
                    // SAFETY: pop transfers an empty allocation owned by this bin, with its layout.
                    unsafe { dealloc(ptr.as_ptr(), bin.layout) };
                    self.bytes -= bin.layout.size();
                    self.evicted = self.evicted.saturating_add(1);
                }
            }
            let bin = &mut self.bins[cap];
            // SAFETY: The caller transfers empty storage of sufficient size for this link. Its
            // alignment may be one, so the link is written and read with unaligned operations.
            unsafe {
                ptr.as_ptr()
                    .cast::<Option<NonNull<u8>>>()
                    .write_unaligned(bin.head)
            };
            bin.head = Some(ptr);
            bin.layout = layout;
            self.bytes += layout.size();
            self.peak_bytes = self.peak_bytes.max(self.bytes);
            true
        }
    }

    impl Drop for Cache {
        fn drop(&mut self) {
            for bin in &mut self.bins {
                while let Some(ptr) = bin.pop() {
                    // SAFETY: Every cached pointer is exclusively owned and has the bin's layout.
                    unsafe { dealloc(ptr.as_ptr(), bin.layout) };
                }
            }
        }
    }

    // SAFETY: The cache exclusively owns all linked allocations and only accesses them through
    // mutable access. Pool's mutex serializes access when shared between threads.
    unsafe impl Send for Cache {}

    #[cfg(test)]
    mod tests {
        use super::*;

        fn layout(cap: usize) -> Layout {
            Layout::array::<u64>(cap).unwrap()
        }

        fn pool(budget: usize) -> Pool {
            Pool {
                cache: Mutex::new(Cache::new(budget)),
                report: false,
            }
        }

        fn release(pool: &Pool, allocation: (NonNull<u8>, usize)) {
            // SAFETY: Tests pass exclusively owned, empty allocations from pool.allocate.
            unsafe { pool.release(allocation.0, allocation.1, layout(allocation.1)) };
        }

        #[test]
        fn test_best_fit_and_oversize_limit() {
            let pool = pool(4096);
            let large = pool.allocate(12, layout);
            let small = pool.allocate(10, layout);
            release(&pool, large);
            release(&pool, small);
            let reused = pool.allocate(9, layout);
            assert_eq!(reused, small);
            let exact = pool.allocate(7, layout);
            assert_eq!(exact.1, 7);
            release(&pool, reused);
            release(&pool, exact);
        }

        #[test]
        fn test_byte_budget_and_cold_eviction() {
            let pool = pool(160);
            let a = pool.allocate(8, layout);
            let b = pool.allocate(9, layout);
            let c = pool.allocate(10, layout);
            release(&pool, a);
            release(&pool, b);
            let hot = pool.allocate(8, layout);
            release(&pool, hot);
            release(&pool, c);
            let cache = pool.cache.lock();
            assert!(cache.bins[8].head.is_some());
            assert!(cache.bins[9].head.is_none());
            assert!(cache.bins[10].head.is_some());
            assert_eq!(cache.bytes, 144);
            assert!(cache.peak_bytes <= cache.budget);
            assert_eq!(cache.evicted, 1);
        }

        #[test]
        fn test_layout_compatibility_and_unaligned_links() {
            let pool = pool(4096);
            let packed = |cap| Layout::from_size_align(cap * 5, 1).unwrap();
            let a = pool.allocate(8, packed);
            // SAFETY: a is an empty allocation with packed(a.1)'s layout.
            unsafe { pool.release(a.0, a.1, packed(a.1)) };
            let b = pool.allocate(8, layout);
            assert_ne!(a.0, b.0);
            let c = pool.allocate(8, packed);
            assert_eq!(a, c);
            release(&pool, b);
            // SAFETY: c is the exclusively owned packed allocation taken from the cache.
            unsafe { pool.release(c.0, c.1, packed(c.1)) };

            let tiny = pool.allocate(1, |_| Layout::new::<u8>());
            // SAFETY: tiny owns one byte. The cache must not write a pointer-sized link into it.
            unsafe { pool.release(tiny.0, tiny.1, Layout::new::<u8>()) };
            assert!(pool.cache.lock().bins[1].head.is_none());
        }

        #[test]
        fn test_bypass_and_concurrent_reuse() {
            for budget in [0, 256] {
                let pool = pool(budget);
                let large = pool.allocate(600, layout);
                release(&pool, large);
                std::thread::scope(|scope| {
                    for _ in 0..4 {
                        let pool = &pool;
                        scope.spawn(move || {
                            for cap in 1..=64 {
                                let allocation = pool.allocate(cap, layout);
                                release(pool, allocation);
                            }
                        });
                    }
                });
                assert!(pool.cache.lock().peak_bytes <= budget);
            }
        }
    }
}
