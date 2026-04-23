//! Buffer pool for efficient I/O operations.
//!
//! Provides pooled, aligned buffers that can be reused to reduce allocation
//! overhead. Buffer alignment is configurable: use page alignment for storage I/O
//! (required for direct I/O and DMA), or cache-line alignment for network I/O
//! (reduces fragmentation).
//!
//! # Thread Safety
//!
//! [`BufferPool`] is `Send + Sync` and can be safely shared across threads.
//! Allocation and deallocation are lock-free operations using atomic counters
//! and a lock-free queue ([`crossbeam_queue::ArrayQueue`]).
//!
//! # Pool Lifecycle
//!
//! Each tracked buffer keeps a strong reference to the originating size class.
//! Buffers can outlive the public [`BufferPool`] handle and still return to
//! their original size class.
//! - Untracked fallback allocations store no class reference and deallocate
//!   directly when dropped.
//! - Requests smaller than [`BufferPoolConfig::pool_min_size`] bypass pooling
//!   entirely and return untracked aligned allocations from both
//!   [`BufferPool::try_alloc`] and [`BufferPool::alloc`].
//! - Dropping [`BufferPool`] drains only the shared global freelists,
//!   checked-out buffers and buffers cached in a live thread's local cache can
//!   keep their size class alive until they are dropped or the thread exits.
//!
//! # Size Classes
//!
//! Buffers are organized into power-of-two size classes from `min_size` to
//! `max_size`. For example, with `min_size = 4096` and `max_size = 32768`:
//! - Class 0: 4096 bytes
//! - Class 1: 8192 bytes
//! - Class 2: 16384 bytes
//! - Class 3: 32768 bytes
//!
//! Allocation requests are rounded up to the next size class. Requests larger
//! than `max_size` return [`PoolError::Oversized`] from [`BufferPool::try_alloc`],
//! or fall back to an untracked aligned heap allocation from [`BufferPool::alloc`].
//!
//! # Cache Structure
//!
//! Each size class uses a two-level allocator:
//! - a small per-thread local cache for steady-state same-thread reuse
//! - a shared global freelist for refill and spill between threads
//!
//! When a local cache misses, the pool refills a small batch from the global
//! freelist before attempting to create a new tracked buffer. Returned buffers
//! first try to re-enter the dropping thread's local cache, spilling a bounded
//! batch back to the global freelist if needed.

use super::IoBufMut;
use crate::{
    iobuf::aligned::{AlignedBuffer, PooledBufMut},
    telemetry::metrics::{
        raw::{Counter, Family, Gauge},
        EncodeLabelSet, MetricRegister,
    },
};
use commonware_utils::NZUsize;
use crossbeam_queue::ArrayQueue;
use std::{
    cell::UnsafeCell,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

/// Minimum thread-cache size required before refill/spill starts batching.
///
/// Below this threshold TLS still provides same-thread locality, but batching
/// would degrade to single-buffer moves and add policy complexity without
/// amortizing shared-queue traffic.
const MIN_THREAD_CACHE_BATCHING_CAPACITY: usize = 4;

/// Error returned when buffer pool allocation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolError {
    /// The requested capacity exceeds the maximum buffer size.
    Oversized,
    /// The pool is exhausted for the required size class.
    Exhausted,
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oversized => write!(f, "requested capacity exceeds maximum buffer size"),
            Self::Exhausted => write!(f, "pool exhausted for required size class"),
        }
    }
}

impl std::error::Error for PoolError {}

/// Returns the system page size.
///
/// On Unix systems, queries the actual page size via `sysconf`.
/// On other systems (Windows), defaults to 4KB.
#[cfg(unix)]
fn page_size() -> usize {
    // SAFETY: sysconf is safe to call.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size <= 0 {
        4096 // Safe fallback if sysconf fails
    } else {
        size as usize
    }
}

#[cfg(not(unix))]
#[allow(clippy::missing_const_for_fn)]
fn page_size() -> usize {
    4096
}

/// Returns the cache line size for the current architecture.
///
/// Uses 128 bytes for x86_64 and aarch64 as a conservative estimate that
/// accounts for spatial prefetching. Uses 64 bytes for other architectures.
///
/// See: <https://github.com/crossbeam-rs/crossbeam/blob/983d56b6007ca4c22b56a665a7785f40f55c2a53/crossbeam-utils/src/cache_padded.rs>
const fn cache_line_size() -> usize {
    cfg_if::cfg_if! {
        if #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))] {
            128
        } else {
            64
        }
    }
}

/// Policy for sizing each thread's cache within a buffer pool size class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BufferPoolThreadCacheConfig {
    /// Disable thread-local caching and route all reuse through the shared global freelist.
    Disabled,
    /// Use an exact per-thread cache size for every size class.
    Fixed(NonZeroUsize),
    /// Derive a per-thread cache size from an expected level of parallelism.
    ForParallelism(NonZeroUsize),
}

/// Configuration for a buffer pool.
#[derive(Debug, Clone)]
pub struct BufferPoolConfig {
    /// Minimum request size that should use pooled allocation.
    ///
    /// Requests smaller than this bypass the pool and use direct aligned
    /// allocation instead. A value of `0` means all eligible requests use the
    /// pool.
    pub pool_min_size: usize,
    /// Minimum buffer size. Must be >= alignment and a power of two.
    pub min_size: NonZeroUsize,
    /// Maximum buffer size. Must be a power of two and >= min_size.
    pub max_size: NonZeroUsize,
    /// Maximum number of buffers per size class.
    pub max_per_class: NonZeroUsize,
    /// Whether to pre-allocate all buffers on pool creation.
    pub prefill: bool,
    /// Buffer alignment. Must be a power of two.
    /// Use `page_size()` for storage I/O and `cache_line_size()` for network I/O.
    pub alignment: NonZeroUsize,
    /// Policy for sizing the per-thread local cache in each size class.
    ///
    /// [`Self::with_thread_cache_disabled`] bypasses thread-local caches.
    /// [`Self::with_thread_cache_capacity`] uses an exact per-thread cache size.
    /// [`Self::with_thread_cache_for_parallelism`] derives a size from the
    /// expected level of parallelism.
    pub(crate) thread_cache_config: BufferPoolThreadCacheConfig,
}

impl BufferPoolConfig {
    /// Network I/O preset: cache-line aligned, 1KB to 64KB buffers,
    /// 4096 per class, not prefilled.
    ///
    /// Network operations typically need multiple concurrent buffers per connection
    /// (message, encoding, encryption) so we allow 4096 buffers per size class.
    /// Cache-line alignment is used because network buffers don't require page
    /// alignment for DMA, and smaller alignment reduces internal fragmentation.
    pub const fn for_network() -> Self {
        let cache_line = NZUsize!(cache_line_size());
        Self {
            pool_min_size: 1024,
            min_size: NZUsize!(1024),
            max_size: NZUsize!(64 * 1024),
            max_per_class: NZUsize!(4096),
            prefill: false,
            alignment: cache_line,
            thread_cache_config: BufferPoolThreadCacheConfig::Disabled,
        }
    }

    /// Storage I/O preset: page-aligned, page_size to 8MB buffers, 32 per class,
    /// not prefilled.
    ///
    /// Page alignment is required for direct I/O and efficient DMA transfers.
    pub fn for_storage() -> Self {
        let page = NZUsize!(page_size());
        Self {
            pool_min_size: 1024,
            min_size: page,
            max_size: NZUsize!(8 * 1024 * 1024),
            max_per_class: NZUsize!(64),
            prefill: false,
            alignment: page,
            thread_cache_config: BufferPoolThreadCacheConfig::Disabled,
        }
    }

    /// Returns a copy of this config with a new minimum request size that uses pooling.
    pub const fn with_pool_min_size(mut self, pool_min_size: usize) -> Self {
        self.pool_min_size = pool_min_size;
        self
    }

    /// Returns a copy of this config with a new minimum buffer size.
    pub const fn with_min_size(mut self, min_size: NonZeroUsize) -> Self {
        self.min_size = min_size;
        self
    }

    /// Returns a copy of this config with a new maximum buffer size.
    pub const fn with_max_size(mut self, max_size: NonZeroUsize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Returns a copy of this config with a new maximum number of buffers per size class.
    pub const fn with_max_per_class(mut self, max_per_class: NonZeroUsize) -> Self {
        self.max_per_class = max_per_class;
        self
    }

    /// Returns a copy of this config with an explicit per-thread cache size.
    pub const fn with_thread_cache_capacity(mut self, thread_cache_capacity: NonZeroUsize) -> Self {
        self.thread_cache_config = BufferPoolThreadCacheConfig::Fixed(thread_cache_capacity);
        self
    }

    /// Returns a copy of this config with thread-cache capacity derived from a parallelism hint.
    ///
    /// The final per-thread cache size is resolved when the pool is created, using the final
    /// `max_per_class` value. The derived size reserves half the class budget for the shared
    /// freelist and clamps the local cache to `[1, 8]`.
    pub const fn with_thread_cache_for_parallelism(mut self, parallelism: NonZeroUsize) -> Self {
        self.thread_cache_config = BufferPoolThreadCacheConfig::ForParallelism(parallelism);
        self
    }

    /// Returns a copy of this config with thread-local caching disabled.
    pub const fn with_thread_cache_disabled(mut self) -> Self {
        self.thread_cache_config = BufferPoolThreadCacheConfig::Disabled;
        self
    }

    /// Returns a copy of this config with a new prefill setting.
    pub const fn with_prefill(mut self, prefill: bool) -> Self {
        self.prefill = prefill;
        self
    }

    /// Returns a copy of this config with a new alignment.
    pub const fn with_alignment(mut self, alignment: NonZeroUsize) -> Self {
        self.alignment = alignment;
        self
    }

    /// Returns a copy of this config sized for an approximate tracked-memory budget.
    ///
    /// This computes `max_per_class` as:
    ///
    /// `ceil(budget_bytes / sum(size_class_bytes))`
    ///
    /// where `size_class_bytes` includes every class from `min_size` to `max_size`.
    /// This always rounds up to at least one buffer per size class, so the
    /// resulting estimated capacity may exceed `budget_bytes`.
    pub fn with_budget_bytes(mut self, budget_bytes: NonZeroUsize) -> Self {
        let mut class_bytes = 0usize;
        for i in 0..self.num_classes() {
            class_bytes = class_bytes.saturating_add(self.class_size(i));
        }
        if class_bytes == 0 {
            return self;
        }
        self.max_per_class = NZUsize!(budget_bytes.get().div_ceil(class_bytes));
        self
    }

    /// Validates the configuration, panicking on invalid values.
    ///
    /// # Panics
    ///
    /// - `alignment` is not a power of two
    /// - `min_size` is not a power of two
    /// - `max_size` is not a power of two
    /// - `min_size < alignment`
    /// - `max_size < min_size`
    /// - `pool_min_size > min_size`
    /// - explicit `thread_cache_capacity > max_per_class`
    fn validate(&self) {
        assert!(
            self.alignment.is_power_of_two(),
            "alignment must be a power of two"
        );
        assert!(
            self.min_size.is_power_of_two(),
            "min_size must be a power of two"
        );
        assert!(
            self.max_size.is_power_of_two(),
            "max_size must be a power of two"
        );
        assert!(
            self.min_size >= self.alignment,
            "min_size ({}) must be >= alignment ({})",
            self.min_size,
            self.alignment
        );
        assert!(
            self.max_size >= self.min_size,
            "max_size must be >= min_size"
        );
        assert!(
            self.pool_min_size <= self.min_size.get(),
            "pool_min_size ({}) must be <= min_size ({})",
            self.pool_min_size,
            self.min_size
        );
        if let BufferPoolThreadCacheConfig::Fixed(thread_cache_capacity) = self.thread_cache_config
        {
            assert!(
                thread_cache_capacity <= self.max_per_class,
                "thread_cache_capacity ({}) must be <= max_per_class ({})",
                thread_cache_capacity,
                self.max_per_class
            );
        }
    }

    /// Returns the number of size classes.
    #[inline]
    fn num_classes(&self) -> usize {
        if self.max_size < self.min_size {
            return 0;
        }
        // Classes are: min_size, min_size*2, min_size*4, ..., max_size
        (self.max_size.get() / self.min_size.get()).trailing_zeros() as usize + 1
    }

    /// Returns the size class index for a given size.
    /// Returns None if size > max_size.
    #[inline]
    fn class_index(&self, size: usize) -> Option<usize> {
        if size > self.max_size.get() {
            return None;
        }
        if size <= self.min_size.get() {
            return Some(0);
        }
        // Find the smallest power-of-two class that fits
        let size_class = size.next_power_of_two();
        let index = (size_class / self.min_size.get()).trailing_zeros() as usize;
        if index < self.num_classes() {
            Some(index)
        } else {
            None
        }
    }

    /// Returns the buffer size for a given class index.
    const fn class_size(&self, index: usize) -> usize {
        self.min_size.get() << index
    }

    /// Resolves the effective per-thread cache size for each size class.
    ///
    /// Derived capacities reserve half of the class budget for the shared freelist so
    /// cross-thread reuse remains effective, and are clamped to `[1, 8]` to cap
    /// per-thread retention.
    fn resolve_thread_cache_capacity(&self) -> usize {
        match self.thread_cache_config {
            BufferPoolThreadCacheConfig::Disabled => 0,
            BufferPoolThreadCacheConfig::Fixed(thread_cache_capacity) => {
                thread_cache_capacity.get()
            }
            BufferPoolThreadCacheConfig::ForParallelism(parallelism) => {
                let max_per_class = self.max_per_class.get();
                let effective_threads = parallelism.get().min(max_per_class);
                (max_per_class / (2 * effective_threads)).clamp(1, 8)
            }
        }
    }
}

/// Label for buffer pool metrics, identifying the size class.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SizeClassLabel {
    size_class: u64,
}

/// Metrics for the buffer pool.
struct PoolMetrics {
    /// Number of tracked buffers currently created for the size class.
    created: Family<SizeClassLabel, Gauge>,
    /// Total number of failed allocations (pool exhausted).
    exhausted_total: Family<SizeClassLabel, Counter>,
    /// Total number of oversized allocation requests.
    oversized_total: Counter,
}

impl PoolMetrics {
    fn new(registry: &mut impl MetricRegister) -> Self {
        let metrics = Self {
            created: Family::default(),
            exhausted_total: Family::default(),
            oversized_total: Counter::default(),
        };

        registry.register(
            "buffer_pool_created",
            "Number of tracked buffers currently created for the pool",
            metrics.created.clone(),
        );
        registry.register(
            "buffer_pool_exhausted_total",
            "Total number of failed allocations due to pool exhaustion",
            metrics.exhausted_total.clone(),
        );
        registry.register(
            "buffer_pool_oversized_total",
            "Total number of allocation requests exceeding max buffer size",
            metrics.oversized_total.clone(),
        );

        metrics
    }
}

/// Per-size-class state.
///
/// Each class is a small two-level allocator:
/// - a shared global freelist for tracked buffers visible to all threads
/// - a per-thread local cache for same-thread reuse
/// - a `created` counter that caps the total number of tracked buffers
///
/// Allocation prefers the local cache, then refills from the global freelist,
/// and only creates a new tracked buffer when no free buffer is available and
/// the class still has remaining capacity.
pub(super) struct SizeClass {
    /// Dense global identifier for the TLS cache registry.
    class_id: usize,
    /// The buffer size for this class.
    size: usize,
    /// Buffer alignment.
    alignment: usize,
    /// Maximum number of tracked buffers for this class.
    max: usize,
    /// Global free list of tracked buffers available for reuse.
    global: ArrayQueue<AlignedBuffer>,
    /// Number of tracked buffers currently in existence for this class.
    created: AtomicUsize,
    /// Maximum number of buffers retained in the current thread's local bin.
    thread_cache_capacity: usize,
}

// SAFETY: shared state in `SizeClass` is synchronized through atomics and the
// global queue. Per-thread bins are stored in thread-local registries and only
// accessed by the current thread.
unsafe impl Send for SizeClass {}
// SAFETY: see above.
unsafe impl Sync for SizeClass {}

impl SizeClass {
    /// Creates a new size class with the given parameters.
    ///
    /// If `prefill` is true, allocates `max` buffers upfront and pushes them
    /// into the global freelist.
    fn new(
        class_id: usize,
        size: usize,
        alignment: usize,
        max: usize,
        thread_cache_capacity: usize,
        prefill: bool,
    ) -> Self {
        let freelist = ArrayQueue::new(max);
        let mut created = 0;
        if prefill {
            for _ in 0..max {
                let _ = freelist.push(AlignedBuffer::new(size, alignment));
            }
            created = max;
        }
        Self {
            class_id,
            size,
            alignment,
            max,
            global: freelist,
            created: AtomicUsize::new(created),
            thread_cache_capacity,
        }
    }

    /// Returns a tracked buffer to the global freelist.
    #[inline]
    fn push_global(&self, buffer: AlignedBuffer) {
        self.global.push(buffer).unwrap_or_else(|_| {
            unreachable!("tracked buffer should always fit in the global pool")
        });
    }

    /// Atomically reserves capacity to create one new tracked buffer.
    ///
    /// Returns `true` if the reservation succeeded (i.e. `created < max`),
    /// `false` if the class is at capacity.
    fn try_reserve(&self) -> bool {
        self.created
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |created| {
                (created < self.max).then_some(created + 1)
            })
            .is_ok()
    }
}

/// Free tracked buffer cached in the current thread's TLS registry.
///
/// This is allocator cache state, not a checked-out buffer. The cached
/// `Arc<SizeClass>` is moved back into a checked-out pooled buffer on a local
/// hit, or used to flush the buffer into the shared global freelist when the
/// thread cache spills or is dropped on thread exit.
struct TlsSizeClassCacheEntry {
    buffer: AlignedBuffer,
    class: Arc<SizeClass>,
}

/// Per-class thread-local cache for tracked buffers.
///
/// The hot steady-state path allocates from and returns to this cache. When
/// the cache is full, small bins route overflow directly to the class-global
/// freelist while larger bins spill a batch back to it. When the thread exits
/// its remaining entries are flushed to that same global freelist.
struct TlsSizeClassCache {
    entries: Vec<TlsSizeClassCacheEntry>,
    capacity: usize,
}

impl TlsSizeClassCache {
    /// Creates a new empty cache with the given maximum thread-cache size.
    fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Returns the number of buffers currently in this local cache.
    #[inline]
    const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Removes and returns the most recently cached buffer, if any.
    #[inline]
    fn pop(&mut self) -> Option<TlsSizeClassCacheEntry> {
        self.entries.pop()
    }

    /// Pushes an entry into the local cache, spilling to global if full.
    ///
    /// Small local caches prioritize same-thread locality and route overflow
    /// directly to the global freelist. Once the local cache is large enough
    /// to batch effectively, half the entries are drained to amortize global
    /// queue traffic across future returns.
    fn push(&mut self, entry: TlsSizeClassCacheEntry) {
        if self.entries.len() < self.capacity {
            self.entries.push(entry);
            return;
        }

        if self.capacity < MIN_THREAD_CACHE_BATCHING_CAPACITY {
            entry.class.push_global(entry.buffer);
            return;
        }

        // Spill half the cache to global to make room.
        let spill = self.entries.len().min(self.capacity / 2).max(1);
        for _ in 0..spill {
            let spilled = self
                .entries
                .pop()
                .expect("spill count must not exceed cached entries");
            spilled.class.push_global(spilled.buffer);
        }

        self.entries.push(entry);
    }
}

impl Drop for TlsSizeClassCache {
    fn drop(&mut self) {
        for entry in self.entries.drain(..) {
            entry.class.push_global(entry.buffer);
        }
    }
}

// Each thread owns a sparse registry of per-size-class caches, indexed by the
// global `SizeClass::class_id`.
//
// We intentionally use `Vec<Option<...>>` here:
// - `class_id` values are dense enough for vector indexing to be cheap
// - each thread typically touches only a subset of all size classes
// - `None` represents "this thread has never initialized a cache for this id"
//
// This keeps the hot TLS-hit path to "index and branch" without a hash map or
// any synchronization. The cost is that vectors can accumulate holes over time
// because ids are not recycled.
thread_local! {
    static TLS_SIZE_CLASS_CACHES: UnsafeCell<Vec<Option<TlsSizeClassCache>>> =
        const { UnsafeCell::new(Vec::new()) };
}

// Global allocator for `SizeClass::class_id`.
//
// Ids are monotonic and never reused. This is deliberate: a reused id would
// require generation tracking or equivalent validation on every TLS cache
// access to distinguish a live size class from stale per-thread cache state.
// Keeping ids monotonic makes the TLS fast path cheaper and simpler at the
// cost of leaving holes in `TLS_CLASS_CACHES` over process lifetime.
static NEXT_SIZE_CLASS_ID: AtomicUsize = AtomicUsize::new(0);

/// Utilities for managing the calling thread's local [`BufferPool`] caches.
///
/// Internally, each thread owns a sparse `Vec<Option<TlsSizeClassCache>>`
/// keyed by `SizeClass::class_id`, with one per-size-class cache allocated
/// lazily on first use. Thread exit naturally flushes cached buffers back to
/// the shared global freelist because `TlsSizeClassCache` drains itself in
/// `Drop`.
///
/// This type exists to keep the unsafe TLS access localized. All steady-state
/// cache operations (`pop`, `push`, and `refill`) go through this facade rather
/// than free functions over the `thread_local!` static.
pub struct BufferPoolThreadCache;

impl BufferPoolThreadCache {
    /// Flushes all local caches for the current thread into the global freelists.
    pub fn flush() {
        TLS_SIZE_CLASS_CACHES.with(|bins| {
            // SAFETY: this TLS value is only ever accessed by the current thread.
            let bins = unsafe { &mut *bins.get() };
            for cache in bins.iter_mut() {
                let _ = cache.take();
            }
        });
    }

    /// Pops a cached buffer from the current thread's local cache for the
    /// given size class. Returns `None` if the local cache is empty.
    #[inline]
    fn pop(class: &Arc<SizeClass>) -> Option<TlsSizeClassCacheEntry> {
        Self::with_cache(class.class_id, class.thread_cache_capacity, |cache| {
            cache.pop()
        })
    }

    /// Returns a buffer to the current thread's local cache for the given
    /// size class, spilling to the global freelist if the cache is full.
    #[inline]
    pub(super) fn push(class: Arc<SizeClass>, buffer: AlignedBuffer) {
        let class_id = class.class_id;
        let thread_cache_capacity = class.thread_cache_capacity;
        Self::with_cache(class_id, thread_cache_capacity, |cache| {
            cache.push(TlsSizeClassCacheEntry { buffer, class });
        });
    }

    /// Batch-refills the local cache from the global freelist.
    ///
    /// Pulls up to `target - 1` buffers from global into the local cache. For
    /// small local bins, batching is disabled and this becomes a no-op. Called
    /// after a global pop succeeds, so the caller already holds one buffer and
    /// we warm the cache for subsequent local hits when batching is enabled.
    #[inline]
    fn refill(class: &Arc<SizeClass>, target: usize) {
        Self::with_cache(class.class_id, class.thread_cache_capacity, |cache| {
            while cache.len() + 1 < target {
                let Some(buffer) = class.global.pop() else {
                    break;
                };
                cache.push(TlsSizeClassCacheEntry {
                    buffer,
                    class: class.clone(),
                });
            }
        });
    }

    /// Accesses the current thread's local cache for `class_id`, creating it
    /// lazily on first use, and invokes `f` on it.
    #[inline]
    fn with_cache<R>(
        class_id: usize,
        capacity: usize,
        f: impl FnOnce(&mut TlsSizeClassCache) -> R,
    ) -> R {
        TLS_SIZE_CLASS_CACHES.with(|bins| {
            // SAFETY: this TLS value is only ever accessed by the current thread.
            let bins = unsafe { &mut *bins.get() };
            if class_id >= bins.len() {
                bins.resize_with(class_id + 1, || None);
            }
            let cache = bins[class_id].get_or_insert_with(|| TlsSizeClassCache::new(capacity));
            f(cache)
        })
    }
}

/// Internal allocation result for pooled allocations.
struct Allocation {
    buffer: AlignedBuffer,
    is_new: bool,
    class: Arc<SizeClass>,
}

/// Internal state of the buffer pool.
pub(crate) struct BufferPoolInner {
    config: BufferPoolConfig,
    classes: Vec<Arc<SizeClass>>,
    metrics: PoolMetrics,
}

impl Drop for BufferPoolInner {
    fn drop(&mut self) {
        for class in &self.classes {
            while let Some(buffer) = class.global.pop() {
                class.created.fetch_sub(1, Ordering::Relaxed);
                drop(buffer);
            }
        }
    }
}

impl BufferPoolInner {
    /// Try to allocate a buffer from the given size class.
    ///
    /// Uses a three-tier strategy:
    /// 1. **Thread-local cache** (fast path): no atomics, no contention.
    /// 2. **Global freelist**: atomic pop, then batch-refill the local cache
    ///    when the local bin is large enough to amortize shared-queue traffic.
    /// 3. **New allocation**: reserve capacity via CAS, allocate from heap.
    ///
    /// If `zero_on_new` is true, newly-created buffers are allocated with
    /// `alloc_zeroed`. Reused buffers are never re-zeroed here.
    fn try_alloc(&self, class_index: usize, zero_on_new: bool) -> Option<Allocation> {
        let class = &self.classes[class_index];

        // Fast path: reuse from thread-local cache (no atomics, no metrics).
        if let Some(entry) = BufferPoolThreadCache::pop(class) {
            return Some(Allocation {
                buffer: entry.buffer,
                is_new: false,
                class: entry.class,
            });
        }

        // Medium path: refill from global freelist.
        let target = (class.thread_cache_capacity / 2).max(1);
        if let Some(buffer) = class.global.pop() {
            BufferPoolThreadCache::refill(class, target);
            return Some(Allocation {
                buffer,
                is_new: false,
                class: class.clone(),
            });
        }

        // Slow path: create a new tracked buffer (metrics only here).
        let label = SizeClassLabel {
            size_class: class.size as u64,
        };
        if !class.try_reserve() {
            self.metrics.exhausted_total.get_or_create(&label).inc();
            return None;
        }

        self.metrics.created.get_or_create(&label).inc();
        let buffer = if zero_on_new {
            AlignedBuffer::new_zeroed(class.size, class.alignment)
        } else {
            AlignedBuffer::new(class.size, class.alignment)
        };
        Some(Allocation {
            buffer,
            is_new: true,
            class: class.clone(),
        })
    }
}

/// A pool of reusable, aligned buffers.
///
/// Buffers are organized into power-of-two size classes. When a buffer is requested,
/// the smallest size class that fits is used. Buffers are automatically returned to
/// the pool when dropped.
///
/// # Alignment
///
/// Buffer alignment is guaranteed only at the base pointer (when `cursor == 0`).
/// After calling [`bytes::Buf::advance`], the pointer returned by `as_mut_ptr()` may
/// no longer be aligned. For direct I/O operations that require alignment,
/// do not advance the buffer before use.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<BufferPoolInner>,
}

impl std::fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferPool")
            .field("config", &self.inner.config)
            .field("num_classes", &self.inner.classes.len())
            .finish()
    }
}

impl BufferPool {
    /// Creates a new buffer pool with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if the configuration is invalid.
    pub(crate) fn new(config: BufferPoolConfig, registry: &mut impl MetricRegister) -> Self {
        config.validate();
        let metrics = PoolMetrics::new(registry);
        let mut classes = Vec::with_capacity(config.num_classes());
        let thread_cache_capacity = config.resolve_thread_cache_capacity();
        for i in 0..config.num_classes() {
            let size = config.class_size(i);
            let class_id = NEXT_SIZE_CLASS_ID.fetch_add(1, Ordering::Relaxed);
            let class = Arc::new(SizeClass::new(
                class_id,
                size,
                config.alignment.get(),
                config.max_per_class.get(),
                thread_cache_capacity,
                config.prefill,
            ));
            classes.push(class);
        }

        // Update created metrics after prefill
        if config.prefill {
            for class in &classes {
                let label = SizeClassLabel {
                    size_class: class.size as u64,
                };
                let created = class.global.len() as i64;
                metrics.created.get_or_create(&label).set(created);
            }
        }

        Self {
            inner: Arc::new(BufferPoolInner {
                config,
                classes,
                metrics,
            }),
        }
    }

    /// Returns the size class index for `capacity`, recording oversized metrics on failure.
    #[inline]
    fn class_index_or_record_oversized(&self, capacity: usize) -> Option<usize> {
        let class_index = self.inner.config.class_index(capacity);
        if class_index.is_none() {
            self.inner.metrics.oversized_total.inc();
        }
        class_index
    }

    /// Attempts to allocate a pooled buffer.
    ///
    /// Unlike [`Self::alloc`], this method does not fall back to untracked
    /// allocation on exhaustion or oversized requests. Requests smaller than
    /// [`BufferPoolConfig::pool_min_size`] intentionally bypass pooling and
    /// return an untracked aligned allocation instead.
    ///
    /// The returned buffer has `len() == 0` and `capacity() >= capacity`.
    ///
    /// # Initialization
    ///
    /// The returned buffer contains **uninitialized memory**. Do not read from
    /// it until data has been written.
    ///
    /// # Errors
    ///
    /// - [`PoolError::Oversized`]: `capacity` exceeds `max_size`
    /// - [`PoolError::Exhausted`]: Pool exhausted for required size class
    pub fn try_alloc(&self, capacity: usize) -> Result<IoBufMut, PoolError> {
        if capacity < self.inner.config.pool_min_size {
            let size = capacity.max(1);
            return Ok(IoBufMut::with_alignment(size, self.inner.config.alignment));
        }

        let class_index = self
            .class_index_or_record_oversized(capacity)
            .ok_or(PoolError::Oversized)?;

        let buffer = self
            .inner
            .try_alloc(class_index, false)
            .map(|allocation| PooledBufMut::new(allocation.buffer, allocation.class))
            .ok_or(PoolError::Exhausted)?;
        Ok(IoBufMut::from_pooled(buffer))
    }

    /// Allocates a buffer with capacity for at least `capacity` bytes.
    ///
    /// The returned buffer has `len() == 0` and `capacity() >= capacity`,
    /// matching the semantics of [`IoBufMut::with_capacity`] and
    /// [`bytes::BytesMut::with_capacity`]. Use [`bytes::BufMut::put_slice`] or
    /// other [`bytes::BufMut`] methods to write data to the buffer.
    ///
    /// If the pool can provide a buffer (capacity within limits and pool not
    /// exhausted), returns a pooled buffer that will be returned to the pool
    /// when dropped. Requests smaller than [`BufferPoolConfig::pool_min_size`]
    /// bypass pooling and return an untracked aligned allocation. Otherwise, oversized or
    /// exhausted requests fall back to an untracked aligned heap allocation
    /// that is deallocated when dropped.
    ///
    /// Use [`Self::try_alloc`] if you need pooled-only behavior.
    ///
    /// # Initialization
    ///
    /// The returned buffer contains **uninitialized memory**. Do not read from
    /// it until data has been written.
    pub fn alloc(&self, capacity: usize) -> IoBufMut {
        self.try_alloc(capacity).unwrap_or_else(|_| {
            let size = capacity.max(self.inner.config.min_size.get());
            IoBufMut::with_alignment(size, self.inner.config.alignment)
        })
    }

    /// Allocates a buffer and sets its readable length to `len` without
    /// initializing bytes.
    ///
    /// Equivalent to [`Self::alloc`] followed by [`IoBufMut::set_len`].
    ///
    /// # Safety
    ///
    /// Caller must ensure all bytes are initialized before any read operation.
    pub unsafe fn alloc_len(&self, len: usize) -> IoBufMut {
        let mut buf = self.alloc(len);
        // SAFETY: guaranteed by caller.
        unsafe { buf.set_len(len) };
        buf
    }

    /// Attempts to allocate a zero-initialized pooled buffer.
    ///
    /// Unlike [`Self::alloc_zeroed`], this method does not fall back to
    /// untracked allocation on exhaustion or oversized requests. Requests
    /// smaller than [`BufferPoolConfig::pool_min_size`] intentionally bypass
    /// pooling and return an untracked aligned allocation instead.
    ///
    /// The returned buffer has `len() == len` and `capacity() >= len`.
    ///
    /// # Initialization
    ///
    /// Bytes in `0..len` are initialized to zero. Bytes in `len..capacity`
    /// may be uninitialized.
    ///
    /// # Errors
    ///
    /// - [`PoolError::Oversized`]: `len` exceeds `max_size`
    /// - [`PoolError::Exhausted`]: Pool exhausted for required size class
    pub fn try_alloc_zeroed(&self, len: usize) -> Result<IoBufMut, PoolError> {
        if len < self.inner.config.pool_min_size {
            let size = len.max(1);
            let mut buf = IoBufMut::zeroed_with_alignment(size, self.inner.config.alignment);
            buf.truncate(len);
            return Ok(buf);
        }

        let class_index = self
            .class_index_or_record_oversized(len)
            .ok_or(PoolError::Oversized)?;
        let allocation = self
            .inner
            .try_alloc(class_index, true)
            .ok_or(PoolError::Exhausted)?;

        let mut buf = IoBufMut::from_pooled(PooledBufMut::new(allocation.buffer, allocation.class));
        if allocation.is_new {
            // SAFETY: buffer was allocated with alloc_zeroed, so bytes in 0..len are initialized.
            unsafe { buf.set_len(len) };
        } else {
            // Reused buffers may contain old bytes, re-zero requested readable range.
            // SAFETY: `as_mut_ptr()` is valid for writes up to `capacity() >= len` bytes.
            unsafe {
                std::ptr::write_bytes(buf.as_mut_ptr(), 0, len);
                buf.set_len(len);
            }
        }
        Ok(buf)
    }

    /// Allocates a zero-initialized buffer with readable length `len`.
    ///
    /// The returned buffer has `len() == len` and `capacity() >= len`.
    ///
    /// If the pool can provide a buffer (len within limits and pool not
    /// exhausted), returns a pooled buffer that will be returned to the pool
    /// when dropped. Requests smaller than [`BufferPoolConfig::pool_min_size`]
    /// bypass pooling and return an untracked aligned allocation. Otherwise, oversized or
    /// exhausted requests fall back to an untracked aligned heap allocation
    /// that is deallocated when dropped.
    ///
    /// Use this for read APIs that require an initialized `&mut [u8]`.
    /// This avoids `unsafe set_len` at callsites.
    ///
    /// Use [`Self::try_alloc_zeroed`] if you need pooled-only behavior.
    ///
    /// # Initialization
    ///
    /// Bytes in `0..len` are initialized to zero. Bytes in `len..capacity`
    /// may be uninitialized.
    pub fn alloc_zeroed(&self, len: usize) -> IoBufMut {
        self.try_alloc_zeroed(len).unwrap_or_else(|_| {
            // Pool exhausted or oversized: allocate untracked zeroed memory.
            let size = len.max(self.inner.config.min_size.get());
            let mut buf = IoBufMut::zeroed_with_alignment(size, self.inner.config.alignment);
            buf.truncate(len);
            buf
        })
    }

    /// Returns the pool configuration.
    pub fn config(&self) -> &BufferPoolConfig {
        &self.inner.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{iobuf::IoBuf, telemetry::metrics::Registry};
    use bytes::{Buf, BufMut};
    use std::{
        sync::{mpsc, Arc},
        thread,
    };

    fn test_size_class(size: usize, alignment: usize) -> Arc<SizeClass> {
        Arc::new(SizeClass::new(
            NEXT_SIZE_CLASS_ID.fetch_add(1, Ordering::Relaxed),
            size,
            alignment,
            8,
            4,
            false,
        ))
    }

    fn test_pool(config: BufferPoolConfig) -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(config, &mut registry)
    }

    /// Creates a test config with page alignment.
    fn test_config(min_size: usize, max_size: usize, max_per_class: usize) -> BufferPoolConfig {
        BufferPoolConfig {
            pool_min_size: 0,
            min_size: NZUsize!(min_size),
            max_size: NZUsize!(max_size),
            max_per_class: NZUsize!(max_per_class),
            thread_cache_config: BufferPoolThreadCacheConfig::ForParallelism(NZUsize!(1)),
            prefill: false,
            alignment: NZUsize!(page_size()),
        }
    }

    /// Helper to get the number of checked-out tracked buffers for a size class.
    ///
    /// With TLS enabled, tracked buffers can be free in either the shared
    /// freelist or the current thread's local cache.
    fn get_allocated(pool: &BufferPool, size: usize) -> usize {
        let class_index = pool.inner.config.class_index(size).unwrap();
        let class = &pool.inner.classes[class_index];
        class.created.load(Ordering::Relaxed) - class.global.len() - get_local_len(class)
    }

    /// Helper to get the number of free buffers visible to the current thread.
    fn get_available(pool: &BufferPool, size: usize) -> i64 {
        let class_index = pool.inner.config.class_index(size).unwrap();
        let class = &pool.inner.classes[class_index];
        (class.global.len() + get_local_len(class)) as i64
    }

    /// Helper to get the number of free buffers parked in the current thread's
    /// local cache for a size class.
    fn get_local_len(class: &SizeClass) -> usize {
        TLS_SIZE_CLASS_CACHES.with(|bins| {
            // SAFETY: this TLS value is only ever accessed by the current thread.
            let bins = unsafe { &*bins.get() };
            bins.get(class.class_id)
                .and_then(Option::as_ref)
                .map_or(0, TlsSizeClassCache::len)
        })
    }

    #[test]
    fn test_page_size() {
        let size = page_size();
        assert!(size >= 4096);
        assert!(size.is_power_of_two());
    }

    #[test]
    fn test_config_validation() {
        let page = page_size();
        let config = test_config(page, page * 4, 10);
        config.validate();
    }

    #[test]
    #[should_panic(expected = "thread_cache_capacity (11) must be <= max_per_class (10)")]
    fn test_config_invalid_thread_cache_capacity() {
        let page = page_size();
        let config = test_config(page, page * 4, 10).with_thread_cache_capacity(NZUsize!(11));
        config.validate();
    }

    #[test]
    #[should_panic(expected = "min_size must be a power of two")]
    fn test_config_invalid_min_size() {
        let config = BufferPoolConfig {
            pool_min_size: 0,
            min_size: NZUsize!(3000),
            max_size: NZUsize!(8192),
            max_per_class: NZUsize!(10),
            thread_cache_config: BufferPoolThreadCacheConfig::ForParallelism(NZUsize!(1)),
            prefill: false,
            alignment: NZUsize!(page_size()),
        };
        config.validate();
    }

    #[test]
    fn test_config_class_index() {
        let page = page_size();
        let config = test_config(page, page * 8, 10);

        // Classes: page, page*2, page*4, page*8
        assert_eq!(config.num_classes(), 4);

        assert_eq!(config.class_index(1), Some(0));
        assert_eq!(config.class_index(page), Some(0));
        assert_eq!(config.class_index(page + 1), Some(1));
        assert_eq!(config.class_index(page * 2), Some(1));
        assert_eq!(config.class_index(page * 8), Some(3));
        assert_eq!(config.class_index(page * 8 + 1), None);
    }

    #[test]
    fn test_pool_alloc_and_return() {
        let page = page_size();
        let pool = test_pool(test_config(page, page * 4, 2));

        // Allocate a buffer - returns buffer with len=0, capacity >= requested
        let buf = pool.try_alloc(page).unwrap();
        assert!(buf.capacity() >= page);
        assert_eq!(buf.len(), 0);

        // Drop returns to pool
        drop(buf);

        // Can allocate again
        let buf2 = pool.try_alloc(page).unwrap();
        assert!(buf2.capacity() >= page);
        assert_eq!(buf2.len(), 0);
    }

    #[test]
    fn test_alloc_len_sets_len() {
        let page = page_size();
        let pool = test_pool(test_config(page, page * 4, 2));

        // SAFETY: we immediately initialize all bytes before reading.
        let mut buf = unsafe { pool.alloc_len(100) };
        assert_eq!(buf.len(), 100);
        buf.as_mut().fill(0xAB);
        let frozen = buf.freeze();
        assert_eq!(frozen.as_ref(), &[0xAB; 100]);
    }

    #[test]
    fn test_alloc_zeroed_sets_len_and_zeros() {
        let page = page_size();
        let pool = test_pool(test_config(page, page * 4, 2));

        let buf = pool.alloc_zeroed(100);
        assert_eq!(buf.len(), 100);
        assert!(buf.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_try_alloc_zeroed_sets_len_and_zeros() {
        let page = page_size();
        let pool = test_pool(test_config(page, page * 4, 2));

        let buf = pool.try_alloc_zeroed(page).unwrap();
        assert!(buf.is_pooled());
        assert_eq!(buf.len(), page);
        assert!(buf.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_alloc_zeroed_fallback_uses_untracked_zeroed_buffer() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 1));

        // Exhaust pooled capacity for this class.
        let _pooled = pool.try_alloc(page).unwrap();

        let buf = pool.alloc_zeroed(100);
        assert!(!buf.is_pooled());
        assert_eq!(buf.len(), 100);
        assert!(buf.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_alloc_zeroed_reuses_dirty_pooled_buffer() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 1));

        let mut first = pool.alloc_zeroed(page);
        assert!(first.is_pooled());
        assert!(first.as_ref().iter().all(|&b| b == 0));

        // Dirty the buffer before returning it to the pool.
        first.as_mut().fill(0xAB);
        drop(first);

        let second = pool.alloc_zeroed(page);
        assert!(second.is_pooled());
        assert_eq!(second.len(), page);
        assert!(second.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_requests_smaller_than_pool_min_size_bypass_pool() {
        let pool = test_pool(BufferPoolConfig {
            pool_min_size: 512,
            min_size: NZUsize!(512),
            max_size: NZUsize!(1024),
            max_per_class: NZUsize!(2),
            thread_cache_config: BufferPoolThreadCacheConfig::ForParallelism(NZUsize!(1)),
            prefill: false,
            alignment: NZUsize!(128),
        });

        let buf = pool.try_alloc(200).unwrap();
        assert!(!buf.is_pooled());
        assert_eq!(buf.capacity(), 200);

        let zeroed = pool.try_alloc_zeroed(200).unwrap();
        assert!(!zeroed.is_pooled());
        assert_eq!(zeroed.len(), 200);
        assert!(zeroed.as_ref().iter().all(|&b| b == 0));

        let pooled = pool.try_alloc(512).unwrap();
        assert!(pooled.is_pooled());
        assert_eq!(pooled.capacity(), 512);
    }

    #[test]
    fn test_pool_size_classes() {
        let page = page_size();
        let pool = test_pool(test_config(page, page * 4, 10));

        // Small request gets smallest class
        let buf1 = pool.try_alloc(page).unwrap();
        assert_eq!(buf1.capacity(), page);

        // Larger request gets appropriate class
        let buf2 = pool.try_alloc(page + 1).unwrap();
        assert_eq!(buf2.capacity(), page * 2);

        let buf3 = pool.try_alloc(page * 3).unwrap();
        assert_eq!(buf3.capacity(), page * 4);
    }

    #[test]
    fn test_prefill() {
        let page = NZUsize!(page_size());
        let pool = test_pool(BufferPoolConfig {
            pool_min_size: 0,
            min_size: page,
            max_size: page,
            max_per_class: NZUsize!(5),
            thread_cache_config: BufferPoolThreadCacheConfig::ForParallelism(NZUsize!(1)),
            prefill: true,
            alignment: page,
        });

        // Should be able to allocate max_per_class buffers immediately
        let mut bufs = Vec::new();
        for _ in 0..5 {
            bufs.push(pool.try_alloc(page.get()).expect("alloc should succeed"));
        }

        // Next allocation should fail
        assert!(pool.try_alloc(page.get()).is_err());
    }

    #[test]
    fn test_config_for_network() {
        let config = BufferPoolConfig::for_network();
        config.validate();
        assert_eq!(config.pool_min_size, 1024);
        assert_eq!(config.min_size.get(), 1024);
        assert_eq!(config.max_size.get(), 64 * 1024);
        assert_eq!(config.max_per_class.get(), 4096);
        assert_eq!(
            config.thread_cache_config,
            BufferPoolThreadCacheConfig::Disabled
        );
        assert!(!config.prefill);
        assert_eq!(config.alignment.get(), cache_line_size());
    }

    #[test]
    fn test_config_for_storage() {
        let config = BufferPoolConfig::for_storage();
        config.validate();
        assert_eq!(config.pool_min_size, 1024);
        assert_eq!(config.min_size.get(), page_size());
        assert_eq!(config.max_size.get(), 8 * 1024 * 1024);
        assert_eq!(config.max_per_class.get(), 64);
        assert_eq!(
            config.thread_cache_config,
            BufferPoolThreadCacheConfig::Disabled
        );
        assert!(!config.prefill);
        assert_eq!(config.alignment.get(), page_size());
    }

    #[test]
    fn test_storage_config_supports_default_allocations() {
        // The storage preset's max_size (8 MB) should be allocatable out of the box.
        let pool = test_pool(BufferPoolConfig::for_storage());

        let buf = pool.try_alloc(8 * 1024 * 1024).unwrap();
        assert_eq!(buf.capacity(), 8 * 1024 * 1024);
    }

    #[test]
    fn test_config_builders() {
        let page = NZUsize!(page_size());
        let config = BufferPoolConfig::for_storage()
            .with_pool_min_size(1024)
            .with_max_per_class(NZUsize!(64))
            .with_thread_cache_capacity(NZUsize!(8))
            .with_prefill(true)
            .with_min_size(page)
            .with_max_size(NZUsize!(128 * 1024));

        config.validate();
        assert_eq!(config.pool_min_size, 1024);
        assert_eq!(config.min_size, page);
        assert_eq!(config.max_size.get(), 128 * 1024);
        assert_eq!(config.max_per_class.get(), 64);
        assert_eq!(
            config.thread_cache_config,
            BufferPoolThreadCacheConfig::Fixed(NZUsize!(8))
        );
        assert!(config.prefill);
        // Storage profile alignment stays page-sized unless explicitly changed.
        assert_eq!(config.alignment.get(), page_size());

        // Alignment can be tuned explicitly as long as min_size is also adjusted.
        let aligned = BufferPoolConfig::for_network()
            .with_pool_min_size(256)
            .with_thread_cache_for_parallelism(NZUsize!(4))
            .with_alignment(NZUsize!(256))
            .with_min_size(NZUsize!(256));
        aligned.validate();
        assert_eq!(
            aligned.thread_cache_config,
            BufferPoolThreadCacheConfig::ForParallelism(NZUsize!(4))
        );
        assert_eq!(aligned.alignment.get(), 256);
        assert_eq!(aligned.min_size.get(), 256);
    }

    #[test]
    fn test_parallelism_policy_resolves_thread_cache_capacity() {
        let page = page_size();
        let pool =
            test_pool(test_config(page, page, 64).with_thread_cache_for_parallelism(NZUsize!(8)));
        let class_index = pool.inner.config.class_index(page).unwrap();
        assert_eq!(pool.inner.classes[class_index].thread_cache_capacity, 4);
    }

    #[test]
    fn test_fixed_thread_cache_capacity_overrides_runtime_parallelism() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 64).with_thread_cache_capacity(NZUsize!(7)));
        let class_index = pool.inner.config.class_index(page).unwrap();

        // Fixed capacity should bypass the derived parallelism heuristic.
        assert_eq!(pool.inner.classes[class_index].thread_cache_capacity, 7);
    }

    #[test]
    fn test_disabled_thread_cache_does_not_retain_buffers_locally() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2).with_thread_cache_disabled());
        let class_index = pool.inner.config.class_index(page).unwrap();
        let class = &pool.inner.classes[class_index];

        let tracked = pool.try_alloc(page).expect("tracked allocation");
        drop(tracked);

        // Disabled thread caching still routes returns through the global
        // freelist, but should never retain buffers in the current thread.
        assert_eq!(class.thread_cache_capacity, 0);
        assert_eq!(get_local_len(class), 0);
        assert_eq!(class.global.len(), 1);
    }

    #[test]
    fn test_thread_cache_flush_moves_local_entries_to_global() {
        let page = page_size();
        let pool =
            test_pool(test_config(page, page * 2, 8).with_thread_cache_capacity(NZUsize!(4)));

        // Use two distinct size classes so the test exercises the whole TLS
        // registry, not just a single per-class cache entry.
        let small_index = pool.inner.config.class_index(page).unwrap();
        let large_index = pool.inner.config.class_index(page + 1).unwrap();
        let small_class = &pool.inner.classes[small_index];
        let large_class = &pool.inner.classes[large_index];

        // Return one buffer from each class to the current thread. With local
        // caching enabled, both drops should stay in the thread-local bins.
        let small = pool.try_alloc(page).expect("tracked allocation");
        let large = pool.try_alloc(page + 1).expect("tracked allocation");
        drop(small);
        drop(large);

        // Before flushing, both buffers are only visible via the current
        // thread's local caches, nothing has been pushed to the global queues.
        assert_eq!(get_local_len(small_class), 1);
        assert_eq!(get_local_len(large_class), 1);
        assert_eq!(small_class.global.len(), 0);
        assert_eq!(large_class.global.len(), 0);

        // Flushing should walk the entire TLS registry, drop every local cache,
        // and let each cache's drop implementation return its buffers to the
        // shared global freelists.
        BufferPoolThreadCache::flush();

        // After flush, the current thread retains nothing locally and both
        // buffers are once again visible through their class-global queues.
        assert_eq!(get_local_len(small_class), 0);
        assert_eq!(get_local_len(large_class), 0);
        assert_eq!(small_class.global.len(), 1);
        assert_eq!(large_class.global.len(), 1);
    }

    #[test]
    fn test_config_with_budget_bytes() {
        // Classes: 4, 8, 16 (sum = 28). Budget 280 => max_per_class = 10.
        let config = BufferPoolConfig {
            pool_min_size: 0,
            min_size: NZUsize!(4),
            max_size: NZUsize!(16),
            max_per_class: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::ForParallelism(NZUsize!(1)),
            prefill: false,
            alignment: NZUsize!(4),
        }
        .with_budget_bytes(NZUsize!(280));
        assert_eq!(config.max_per_class.get(), 10);

        // Budget 10 rounds up to one buffer per class.
        let small_budget = BufferPoolConfig {
            pool_min_size: 0,
            min_size: NZUsize!(4),
            max_size: NZUsize!(16),
            max_per_class: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::ForParallelism(NZUsize!(1)),
            prefill: false,
            alignment: NZUsize!(4),
        }
        .with_budget_bytes(NZUsize!(10));
        assert_eq!(small_budget.max_per_class.get(), 1);
    }

    #[test]
    fn test_pool_error_display() {
        assert_eq!(
            PoolError::Oversized.to_string(),
            "requested capacity exceeds maximum buffer size"
        );
        assert_eq!(
            PoolError::Exhausted.to_string(),
            "pool exhausted for required size class"
        );
    }

    #[test]
    fn test_config_invalid_range_edge_paths() {
        // max_size < min_size should yield zero size classes, and budget_bytes
        // should leave max_per_class unchanged (no division by zero).
        let invalid_order = BufferPoolConfig {
            pool_min_size: 0,
            min_size: NZUsize!(8),
            max_size: NZUsize!(4),
            max_per_class: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::ForParallelism(NZUsize!(1)),
            prefill: false,
            alignment: NZUsize!(4),
        };
        assert_eq!(invalid_order.num_classes(), 0);
        let unchanged = invalid_order.clone().with_budget_bytes(NZUsize!(128));
        assert_eq!(unchanged.max_per_class, invalid_order.max_per_class);

        // Non-power-of-two max_size should make the size unreachable via class_index.
        let non_power_two_max = BufferPoolConfig {
            pool_min_size: 0,
            min_size: NZUsize!(8),
            max_size: NZUsize!(12),
            max_per_class: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::ForParallelism(NZUsize!(1)),
            prefill: false,
            alignment: NZUsize!(4),
        };
        assert_eq!(non_power_two_max.class_index(12), None);
    }

    #[test]
    fn test_pool_debug_and_config_accessor() {
        // Debug formatting and config accessor should be consistent.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        let debug = format!("{pool:?}");
        assert!(debug.contains("BufferPool"));
        assert!(debug.contains("num_classes"));
        assert_eq!(pool.config().min_size.get(), page);
    }

    #[test]
    fn test_return_buffer_local_overflow_spills_to_global() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));
        let class_index = pool
            .inner
            .config
            .class_index(page)
            .expect("class exists for page-sized buffer");

        let tracked1 = pool.try_alloc(page).expect("first tracked allocation");
        let tracked2 = pool.try_alloc(page).expect("second tracked allocation");

        // The first return should stay entirely in the current thread's local cache.
        drop(tracked1);
        assert_eq!(pool.inner.classes[class_index].global.len(), 0);
        assert_eq!(get_local_len(&pool.inner.classes[class_index]), 1);

        // Returning another tracked buffer should route overflow to the global
        // freelist and retain one in the current thread's local bin.
        drop(tracked2);
        assert_eq!(pool.inner.classes[class_index].global.len(), 1);
        assert_eq!(get_local_len(&pool.inner.classes[class_index]), 1);
        assert_eq!(get_available(&pool, page), 2);
    }

    #[test]
    fn test_small_local_cache_overflow_preserves_locality() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        // With `thread_cache_capacity == 1`, the first return stays local and the
        // second overflows directly to global instead of spilling the hot
        // local entry through the shared queue.
        let mut tracked1 = pool.try_alloc(page).expect("first tracked allocation");
        let ptr1 = tracked1.as_mut_ptr();
        let mut tracked2 = pool.try_alloc(page).expect("second tracked allocation");
        let ptr2 = tracked2.as_mut_ptr();

        drop(tracked1);
        drop(tracked2);

        let mut reused_local = pool.try_alloc(page).expect("reuse from local cache");
        assert_eq!(reused_local.as_mut_ptr(), ptr1);

        let mut reused_global = pool.try_alloc(page).expect("reuse from global freelist");
        assert_eq!(reused_global.as_mut_ptr(), ptr2);
    }

    #[test]
    fn test_large_local_cache_batches_overflow_and_refill() {
        let page = page_size();
        let threads = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        let max_per_class = threads * 8;
        let pool = test_pool(test_config(page, page, max_per_class));
        let class_index = pool
            .inner
            .config
            .class_index(page)
            .expect("class exists for page-sized buffer");
        let class = &pool.inner.classes[class_index];

        assert!(class.thread_cache_capacity >= MIN_THREAD_CACHE_BATCHING_CAPACITY);

        // Drop enough distinct checked-out buffers to force an overflow from a
        // full local cache. Large bins should spill half the entries to global
        // and keep the remainder local for fast same-thread reuse.
        let mut bufs = Vec::new();
        for _ in 0..class.thread_cache_capacity + 1 {
            bufs.push(pool.try_alloc(page).expect("tracked allocation"));
        }
        for buf in bufs {
            drop(buf);
        }

        assert_eq!(get_local_len(class), class.thread_cache_capacity / 2 + 1);
        assert_eq!(class.global.len(), class.thread_cache_capacity / 2);

        // Drain the local half, then hit global once. That global pop should
        // batch-refill the local cache back up to the configured target.
        let mut reused = Vec::new();
        for _ in 0..class.thread_cache_capacity / 2 + 1 {
            reused.push(pool.try_alloc(page).expect("local reuse"));
        }
        assert_eq!(get_local_len(class), 0);
        assert_eq!(class.global.len(), class.thread_cache_capacity / 2);

        let _global = pool.try_alloc(page).expect("global reuse with refill");
        assert_eq!(get_local_len(class), class.thread_cache_capacity / 2 - 1);
        assert_eq!(class.global.len(), 0);
    }

    #[test]
    fn test_tls_refill_stops_when_global_runs_empty() {
        let class = test_size_class(64, 64);

        // A short global freelist should refill only what exists, then stop.
        class.push_global(AlignedBuffer::new(class.size, class.alignment));
        BufferPoolThreadCache::refill(&class, MIN_THREAD_CACHE_BATCHING_CAPACITY);

        assert_eq!(get_local_len(&class), 1);
        assert_eq!(class.global.len(), 0);
    }

    #[test]
    fn test_tls_size_class_cache_push_tolerates_empty_spill() {
        let class = test_size_class(64, 64);
        let mut cache = TlsSizeClassCache {
            entries: Vec::new(),
            capacity: 0,
        };

        // Small local capacities should bypass batching and push straight to global.
        cache.push(TlsSizeClassCacheEntry {
            buffer: AlignedBuffer::new(class.size, class.alignment),
            class,
        });
        drop(cache);
    }

    #[test]
    #[should_panic(expected = "tracked buffer should always fit in the global pool")]
    fn test_push_global_panics_when_global_queue_is_inconsistently_full() {
        let class = Arc::new(SizeClass::new(
            NEXT_SIZE_CLASS_ID.fetch_add(1, Ordering::Relaxed),
            64,
            64,
            1,
            1,
            false,
        ));

        // Overfilling the fixed-size global queue should trip the invariant.
        class.push_global(AlignedBuffer::new(64, 64));
        class.push_global(AlignedBuffer::new(64, 64));
    }

    #[test]
    fn test_pooled_debug_and_empty_into_bytes_paths() {
        // Debug formatting for pooled mutable/immutable wrappers, and empty
        // into_bytes should detach without retaining the pool allocation.
        let page = page_size();
        let class = test_size_class(page, page);

        // Mutable pooled debug should include cursor position.
        let pooled_mut_debug = {
            let pooled_mut = PooledBufMut::new(AlignedBuffer::new(page, page), Arc::clone(&class));
            format!("{pooled_mut:?}")
        };
        assert!(pooled_mut_debug.contains("PooledBufMut"));
        assert!(pooled_mut_debug.contains("cursor"));

        // Empty mutable buffer converts to empty Bytes without retaining pool memory.
        let empty_from_mut = PooledBufMut::new(AlignedBuffer::new(page, page), Arc::clone(&class));
        assert!(empty_from_mut.into_bytes().is_empty());

        // Immutable pooled debug should include capacity.
        let pooled = PooledBufMut::new(AlignedBuffer::new(page, page), class).into_pooled();
        let pooled_debug = format!("{pooled:?}");
        assert!(pooled_debug.contains("PooledBuf"));
        assert!(pooled_debug.contains("capacity"));
        assert!(pooled.into_bytes().is_empty());
    }

    #[test]
    fn test_freeze_returns_buffer_to_pool() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        // Initially: 0 allocated, 0 available
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 0);

        // Allocate and freeze
        let buf = pool.try_alloc(page).unwrap();
        assert_eq!(get_allocated(&pool, page), 1);
        assert_eq!(get_available(&pool, page), 0);

        let iobuf = buf.freeze();
        // Still allocated (held by IoBuf)
        assert_eq!(get_allocated(&pool, page), 1);

        // Drop the IoBuf - buffer should return to pool
        drop(iobuf);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_refcount_and_copy_to_bytes_paths() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        // Refcount behavior:
        // - clone/slice keep the pooled allocation alive
        // - empty slice does not keep ownership
        {
            let mut buf = pool.try_alloc(page).unwrap();
            buf.put_slice(&[0xAA; 100]);
            let iobuf = buf.freeze();
            let clone = iobuf.clone();
            let slice = iobuf.slice(10..40);
            let empty = iobuf.slice(10..10);
            assert!(empty.is_empty());
            drop(iobuf);
            assert_eq!(get_allocated(&pool, page), 1);
            drop(slice);
            assert_eq!(get_allocated(&pool, page), 1);
            drop(clone);
            assert_eq!(get_allocated(&pool, page), 0);
        }

        // IoBuf::copy_to_bytes behavior:
        // - zero-length copy is empty and non-advancing
        // - partial copy advances while keeping ownership alive
        // - full drain transfers ownership out of source
        // - zero-length copy on already-empty source stays detached
        {
            let mut buf = pool.try_alloc(page).unwrap();
            buf.put_slice(&[0x42; 100]);
            let mut iobuf = buf.freeze();

            let zero = iobuf.copy_to_bytes(0);
            assert!(zero.is_empty());
            assert_eq!(iobuf.remaining(), 100);

            let partial = iobuf.copy_to_bytes(30);
            assert_eq!(&partial[..], &[0x42; 30]);
            assert_eq!(iobuf.remaining(), 70);

            let rest = iobuf.copy_to_bytes(70);
            assert_eq!(&rest[..], &[0x42; 70]);
            assert_eq!(iobuf.remaining(), 0);

            // Zero-length copy on empty should not transfer ownership.
            let empty = iobuf.copy_to_bytes(0);
            assert!(empty.is_empty());

            drop(iobuf);
            assert_eq!(get_allocated(&pool, page), 1);
            drop(zero);
            drop(partial);
            assert_eq!(get_allocated(&pool, page), 1);
            drop(rest);
            assert_eq!(get_allocated(&pool, page), 0);
        }

        // IoBufMut::copy_to_bytes mirrors the immutable ownership semantics.
        {
            let buf = pool.try_alloc(page).unwrap();
            let mut iobufmut = buf;
            iobufmut.put_slice(&[0x7E; 100]);

            let zero = iobufmut.copy_to_bytes(0);
            assert!(zero.is_empty());
            assert_eq!(iobufmut.remaining(), 100);

            let partial = iobufmut.copy_to_bytes(30);
            assert_eq!(&partial[..], &[0x7E; 30]);
            assert_eq!(iobufmut.remaining(), 70);

            let rest = iobufmut.copy_to_bytes(70);
            assert_eq!(&rest[..], &[0x7E; 70]);
            assert_eq!(iobufmut.remaining(), 0);

            drop(iobufmut);
            assert_eq!(get_allocated(&pool, page), 1);
            drop(zero);
            drop(partial);
            assert_eq!(get_allocated(&pool, page), 1);
            drop(rest);
            assert_eq!(get_allocated(&pool, page), 0);
        }
    }

    #[test]
    fn test_iobuf_to_iobufmut_conversion_reuses_pool_for_non_full_unique_view() {
        // IoBuf -> IoBufMut should recover pooled ownership for unique non-full views.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        let buf = pool.try_alloc(page).unwrap();
        assert_eq!(get_allocated(&pool, page), 1);

        let iobuf = buf.freeze();
        assert_eq!(get_allocated(&pool, page), 1);

        let iobufmut: IoBufMut = iobuf.into();

        // Conversion reused pooled storage instead of copying.
        assert_eq!(
            get_allocated(&pool, page),
            1,
            "pooled buffer should remain allocated after zero-copy IoBuf->IoBufMut conversion"
        );
        assert_eq!(get_available(&pool, page), 0);

        // Dropping returns the pooled buffer.
        drop(iobufmut);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_iobuf_to_iobufmut_conversion_preserves_full_unique_view() {
        // IoBuf -> IoBufMut via From should preserve data and keep pooled
        // ownership for a fully-written unique view.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        // Fill a pooled buffer completely and freeze.
        let mut buf = pool.try_alloc(page).unwrap();
        buf.put_slice(&vec![0xEE; page]);
        let iobuf = buf.freeze();

        // Convert back to mutable; should reuse pooled storage.
        let iobufmut: IoBufMut = iobuf.into();
        assert_eq!(iobufmut.len(), page);
        assert!(iobufmut.as_ref().iter().all(|&b| b == 0xEE));
        assert_eq!(get_allocated(&pool, page), 1);
        assert_eq!(get_available(&pool, page), 0);

        // Dropping returns the buffer to the pool.
        drop(iobufmut);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_iobuf_try_into_mut_recycles_full_unique_view() {
        // try_into_mut on a uniquely-owned full-view pooled IoBuf should recover
        // mutable ownership without copying, preserving data and pool tracking.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        let mut buf = pool.try_alloc(page).unwrap();
        buf.put_slice(&vec![0xAB; page]);
        let iobuf = buf.freeze();
        assert_eq!(get_allocated(&pool, page), 1);

        // Unique full view should recycle.
        let recycled = iobuf
            .try_into_mut()
            .expect("unique full-view pooled buffer should recycle");
        assert_eq!(recycled.len(), page);
        assert!(recycled.as_ref().iter().all(|&b| b == 0xAB));
        assert_eq!(recycled.capacity(), page);
        assert_eq!(get_allocated(&pool, page), 1);

        drop(recycled);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_iobuf_try_into_mut_succeeds_for_unique_slice_and_fails_for_shared() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        // Unique sliced views can recover mutable ownership without copying.
        let mut buf = pool.try_alloc(page).unwrap();
        buf.put_slice(&vec![0xCD; page]);
        let iobuf = buf.freeze();
        let sliced = iobuf.slice(1..page);
        drop(iobuf);
        let recycled = sliced
            .try_into_mut()
            .expect("unique sliced pooled buffer should recycle");
        assert_eq!(recycled.len(), page - 1);
        assert!(recycled.as_ref().iter().all(|&b| b == 0xCD));
        assert_eq!(recycled.capacity(), page - 1);
        assert_eq!(get_allocated(&pool, page), 1);
        drop(recycled);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);

        // Shared views still cannot recover mutable ownership.
        let mut buf = pool.try_alloc(page).unwrap();
        buf.put_slice(&vec![0xEF; page]);
        let iobuf = buf.freeze();
        let cloned = iobuf.clone();
        let iobuf = iobuf
            .try_into_mut()
            .expect_err("shared pooled buffer must not convert to mutable");

        drop(cloned);
        drop(iobuf);
        assert_eq!(get_allocated(&pool, page), 0);
        assert!(get_available(&pool, page) >= 1);
    }

    #[test]
    fn test_multithreaded_alloc_freeze_return() {
        let page = page_size();
        let pool = Arc::new(test_pool(test_config(page, page, 100)));

        let mut handles = vec![];

        // Reduce iterations under miri (atomics are slow)
        cfg_if::cfg_if! {
            if #[cfg(miri)] {
                let iterations = 100;
            } else {
                let iterations = 1000;
            }
        }

        // Spawn multiple threads that allocate, freeze, clone, and drop
        for _ in 0..10 {
            let pool = pool.clone();
            let handle = thread::spawn(move || {
                for _ in 0..iterations {
                    let buf = pool.try_alloc(page).unwrap();
                    let iobuf = buf.freeze();

                    // Clone a few times
                    let clones: Vec<_> = (0..5).map(|_| iobuf.clone()).collect();
                    drop(iobuf);

                    // Drop clones
                    for clone in clones {
                        drop(clone);
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Worker threads may retain free buffers in their own local caches, so
        // the main thread cannot assert that all of them are visible here.
        // It should still be able to allocate successfully once the workers finish.
        let _buf = pool
            .try_alloc(page)
            .expect("pool should remain usable after multithreaded test");
    }

    #[test]
    fn test_cross_thread_buffer_return() {
        // Allocate on one thread, freeze, send to another thread, drop there
        let page = page_size();
        let pool = test_pool(test_config(page, page, 100));

        let (tx, rx) = mpsc::channel();

        // Allocate and freeze on main thread
        for _ in 0..50 {
            let buf = pool.try_alloc(page).unwrap();
            let iobuf = buf.freeze();
            tx.send(iobuf).unwrap();
        }
        drop(tx);

        // Receive and drop on another thread. Those returns should populate the
        // dropping thread's local cache, so allocations on that same thread
        // should be able to reuse them immediately.
        let handle = thread::spawn(move || {
            while let Ok(iobuf) = rx.recv() {
                drop(iobuf);
            }

            let class_index = pool
                .inner
                .config
                .class_index(page)
                .expect("class exists for page-sized buffer");
            assert!(
                get_local_len(&pool.inner.classes[class_index]) >= 1,
                "dropping thread should retain returned buffers in its local cache"
            );

            for _ in 0..50 {
                let _buf = pool
                    .try_alloc(page)
                    .expect("dropping thread should be able to reuse returned buffers");
            }
        });

        handle.join().unwrap();
    }

    #[test]
    fn test_thread_exit_flushes_local_bin() {
        // When a thread exits, its TLS cache Drop flushes buffers back to the
        // global freelist, making them available to other threads.
        let page = page_size();
        let pool = Arc::new(test_pool(test_config(page, page, 1)));

        // Allocate and return a buffer on a worker thread, then let it exit.
        let worker_pool = pool.clone();
        thread::spawn(move || {
            let buf = worker_pool
                .try_alloc(page)
                .expect("worker should allocate tracked buffer");
            drop(buf);
        })
        .join()
        .expect("worker thread should exit cleanly");

        // After thread exit, the buffer should be in the global freelist (not
        // stuck in a dead thread's local cache).
        let class_index = pool
            .inner
            .config
            .class_index(page)
            .expect("class exists for page-sized buffer");
        assert_eq!(pool.inner.classes[class_index].global.len(), 1);
        assert_eq!(get_local_len(&pool.inner.classes[class_index]), 0);

        // The flushed buffer should be reusable from the main thread.
        let _buf = pool
            .try_alloc(page)
            .expect("thread-exited local buffer should be reusable");
    }

    #[test]
    fn test_pool_drop_drains_global_freelist() {
        // Dropping the pool should immediately reclaim globally-visible free
        // tracked buffers, while leaving TLS-cached buffers alone.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));
        let class_index = pool
            .inner
            .config
            .class_index(page)
            .expect("class exists for page-sized buffer");
        let class = Arc::clone(&pool.inner.classes[class_index]);

        // Return one buffer to the current thread's local cache and overflow
        // the other into the shared global freelist.
        let buf1 = pool.try_alloc(page).unwrap();
        let buf2 = pool.try_alloc(page).unwrap();
        drop(buf1);
        drop(buf2);

        assert_eq!(class.global.len(), 1);
        assert_eq!(get_local_len(&class), 1);

        // Pool drop should drain only the global freelist. The thread-local
        // cache remains untouched until thread exit.
        drop(pool);

        assert_eq!(class.global.len(), 0);
        assert_eq!(get_local_len(&class), 1);
        assert_eq!(class.created.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_pool_dropped_before_buffer() {
        // What happens if the pool is dropped while buffers are still in use?
        // The size class remains alive until the last tracked buffer is dropped.

        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        let mut buf = pool.try_alloc(page).unwrap();
        buf.put_slice(&[0u8; 100]);
        let iobuf = buf.freeze();

        // Drop the pool while buffer is still alive
        drop(pool);

        // Buffer should still be usable
        assert_eq!(iobuf.len(), 100);

        // Dropping the buffer should not panic and should return to the retained size class.
        drop(iobuf);
        // No assertion here - we just want to make sure it doesn't panic
    }

    #[test]
    fn test_pool_exhaustion_and_recovery() {
        // Test pool exhaustion and recovery.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 3));

        // Exhaust the pool
        let buf1 = pool.try_alloc(page).expect("first alloc");
        let buf2 = pool.try_alloc(page).expect("second alloc");
        let buf3 = pool.try_alloc(page).expect("third alloc");
        assert!(pool.try_alloc(page).is_err(), "pool should be exhausted");

        // Return one buffer
        drop(buf1);

        // Should be able to allocate again
        let buf4 = pool.try_alloc(page).expect("alloc after return");
        assert!(pool.try_alloc(page).is_err(), "pool exhausted again");

        // Return all and verify freelist reuse
        drop(buf2);
        drop(buf3);
        drop(buf4);

        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 3);

        // Allocate again - should reuse from freelist
        let _buf5 = pool.try_alloc(page).expect("reuse from freelist");
        assert_eq!(get_available(&pool, page), 2);
    }

    #[test]
    fn test_try_alloc_errors() {
        // Test try_alloc error variants.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        // Oversized request
        let result = pool.try_alloc(page * 10);
        assert_eq!(result.unwrap_err(), PoolError::Oversized);

        // Exhaust pool
        let _buf1 = pool.try_alloc(page).unwrap();
        let _buf2 = pool.try_alloc(page).unwrap();
        let result = pool.try_alloc(page);
        assert_eq!(result.unwrap_err(), PoolError::Exhausted);
    }

    #[test]
    fn test_try_alloc_zeroed_errors() {
        // try_alloc_zeroed should return the same error variants as try_alloc.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        // Oversized request.
        let result = pool.try_alloc_zeroed(page * 10);
        assert_eq!(result.unwrap_err(), PoolError::Oversized);

        // Exhaust pool, then verify Exhausted error.
        let _buf1 = pool.try_alloc_zeroed(page).unwrap();
        let _buf2 = pool.try_alloc_zeroed(page).unwrap();
        let result = pool.try_alloc_zeroed(page);
        assert_eq!(result.unwrap_err(), PoolError::Exhausted);
    }

    #[test]
    fn test_fallback_allocation() {
        // Test fallback allocation when pool is exhausted or oversized.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        // Exhaust the pool
        let buf1 = pool.try_alloc(page).unwrap();
        let buf2 = pool.try_alloc(page).unwrap();
        assert!(buf1.is_pooled());
        assert!(buf2.is_pooled());

        // Fallback via alloc() when exhausted - still aligned, but untracked
        let mut fallback_exhausted = pool.alloc(page);
        assert!(!fallback_exhausted.is_pooled());
        assert!((fallback_exhausted.as_mut_ptr() as usize).is_multiple_of(page));

        // Fallback via alloc() when oversized - still aligned, but untracked
        let mut fallback_oversized = pool.alloc(page * 10);
        assert!(!fallback_oversized.is_pooled());
        assert!((fallback_oversized.as_mut_ptr() as usize).is_multiple_of(page));

        // Verify pool counters unchanged by fallback allocations
        assert_eq!(get_allocated(&pool, page), 2);

        // Drop fallback buffers - should not affect pool counters
        drop(fallback_exhausted);
        drop(fallback_oversized);
        assert_eq!(get_allocated(&pool, page), 2);

        // Drop tracked buffers - counters should decrease
        drop(buf1);
        drop(buf2);
        assert_eq!(get_allocated(&pool, page), 0);
    }

    #[test]
    fn test_is_pooled() {
        // IoBufMut from the pool should report is_pooled, while heap-backed
        // buffers should not.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 10));

        let pooled = pool.try_alloc(page).unwrap();
        assert!(pooled.is_pooled());

        let owned = IoBufMut::with_capacity(100);
        assert!(!owned.is_pooled());
    }

    #[test]
    fn test_iobuf_is_pooled() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        let pooled = pool.try_alloc(page).unwrap().freeze();
        assert!(pooled.is_pooled());

        // Oversized alloc uses untracked fallback allocation.
        let fallback = pool.alloc(page * 10).freeze();
        assert!(!fallback.is_pooled());

        let bytes = IoBuf::copy_from_slice(b"hello");
        assert!(!bytes.is_pooled());
    }

    #[test]
    fn test_buffer_alignment() {
        let page = page_size();
        let cache_line = cache_line_size();
        // Reduce max_per_class under miri (atomics are slow)
        cfg_if::cfg_if! {
            if #[cfg(miri)] {
                let storage_config = BufferPoolConfig {
                    max_per_class: NZUsize!(32),
                    ..BufferPoolConfig::for_storage()
                };
                let network_config = BufferPoolConfig {
                    max_per_class: NZUsize!(32),
                    ..BufferPoolConfig::for_network()
                };
            } else {
                let storage_config = BufferPoolConfig::for_storage();
                let network_config = BufferPoolConfig::for_network();
            }
        }

        // Storage preset - page aligned
        let storage_buffer_pool = test_pool(storage_config);
        let mut buf = storage_buffer_pool.try_alloc(100).unwrap();
        assert_eq!(
            buf.as_mut_ptr() as usize % page,
            0,
            "storage buffer not page-aligned"
        );

        // Network preset - cache-line aligned
        let network_buffer_pool = test_pool(network_config);
        let mut buf = network_buffer_pool.try_alloc(100).unwrap();
        assert_eq!(
            buf.as_mut_ptr() as usize % cache_line,
            0,
            "network buffer not cache-line aligned"
        );
    }
}
