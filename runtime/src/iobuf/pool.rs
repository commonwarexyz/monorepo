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
//! The pool uses reference counting internally. Buffers hold a weak reference
//! to the pool, so:
//! - If a buffer is returned after the pool is dropped, it is deallocated
//!   directly instead of being returned to the freelist.
//! - The pool can be dropped while buffers are still in use; those buffers
//!   remain valid and will be deallocated when they are dropped.
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

use super::{IoBuf, IoBufMut};
use bytes::{Buf, BufMut, Bytes};
use commonware_utils::NZUsize;
use crossbeam_queue::ArrayQueue;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::Registry,
};
use std::{
    alloc::{alloc, alloc_zeroed, dealloc, handle_alloc_error, Layout},
    mem::ManuallyDrop,
    num::NonZeroUsize,
    ops::{Bound, RangeBounds},
    ptr::NonNull,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Weak,
    },
};

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

/// Configuration for a buffer pool.
#[derive(Debug, Clone)]
pub struct BufferPoolConfig {
    /// Minimum buffer size. Must be >= alignment and a power of two.
    pub min_size: NonZeroUsize,
    /// Maximum buffer size. Must be a power of two and >= min_size.
    pub max_size: NonZeroUsize,
    /// Maximum number of buffers per size class.
    pub max_per_class: NonZeroUsize,
    /// Whether to pre-allocate all buffers on pool creation.
    pub prefill: bool,
    /// Buffer alignment. Must be a power of two.
    /// Use `page_size()` for storage I/O, `cache_line_size()` for network I/O.
    pub alignment: NonZeroUsize,
}

impl BufferPoolConfig {
    /// Network I/O preset: cache-line aligned, cache_line_size to 64KB buffers,
    /// 4096 per class, not prefilled.
    ///
    /// Network operations typically need multiple concurrent buffers per connection
    /// (message, encoding, encryption) so we allow 4096 buffers per size class.
    /// Cache-line alignment is used because network buffers don't require page
    /// alignment for DMA, and smaller alignment reduces internal fragmentation.
    pub const fn for_network() -> Self {
        let cache_line = NZUsize!(cache_line_size());
        Self {
            min_size: cache_line,
            max_size: NZUsize!(64 * 1024),
            max_per_class: NZUsize!(4096),
            prefill: false,
            alignment: cache_line,
        }
    }

    /// Storage I/O preset: page-aligned, page_size to 64KB buffers, 32 per class,
    /// not prefilled.
    ///
    /// Page alignment is required for direct I/O and efficient DMA transfers.
    pub fn for_storage() -> Self {
        let page = NZUsize!(page_size());
        Self {
            min_size: page,
            max_size: NZUsize!(64 * 1024),
            max_per_class: NZUsize!(32),
            prefill: false,
            alignment: page,
        }
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
    }

    /// Returns the number of size classes.
    fn num_classes(&self) -> usize {
        if self.max_size < self.min_size {
            return 0;
        }
        // Classes are: min_size, min_size*2, min_size*4, ..., max_size
        (self.max_size.get() / self.min_size.get()).trailing_zeros() as usize + 1
    }

    /// Returns the size class index for a given size.
    /// Returns None if size > max_size.
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
}

/// Label for buffer pool metrics, identifying the size class.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SizeClassLabel {
    size_class: u64,
}

/// Metrics for the buffer pool.
struct PoolMetrics {
    /// Number of buffers currently allocated (out of pool).
    allocated: Family<SizeClassLabel, Gauge>,
    /// Number of buffers available in the pool.
    available: Family<SizeClassLabel, Gauge>,
    /// Total number of successful allocations.
    allocations_total: Family<SizeClassLabel, Counter>,
    /// Total number of failed allocations (pool exhausted).
    exhausted_total: Family<SizeClassLabel, Counter>,
    /// Total number of oversized allocation requests.
    oversized_total: Counter,
}

impl PoolMetrics {
    fn new(registry: &mut Registry) -> Self {
        let metrics = Self {
            allocated: Family::default(),
            available: Family::default(),
            allocations_total: Family::default(),
            exhausted_total: Family::default(),
            oversized_total: Counter::default(),
        };

        registry.register(
            "buffer_pool_allocated",
            "Number of buffers currently allocated from the pool",
            metrics.allocated.clone(),
        );
        registry.register(
            "buffer_pool_available",
            "Number of buffers available in the pool",
            metrics.available.clone(),
        );
        registry.register(
            "buffer_pool_allocations_total",
            "Total number of successful buffer allocations",
            metrics.allocations_total.clone(),
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

/// An aligned buffer.
///
/// The buffer is allocated with the specified alignment for efficient I/O operations.
/// Deallocates itself on drop using the stored layout.
pub(crate) struct AlignedBuffer {
    ptr: NonNull<u8>,
    layout: Layout,
}

// SAFETY: AlignedBuffer owns its memory and can be sent between threads.
unsafe impl Send for AlignedBuffer {}
// SAFETY: AlignedBuffer's memory is not shared (no interior mutability of pointer).
unsafe impl Sync for AlignedBuffer {}

impl AlignedBuffer {
    /// Allocates a new buffer with the given capacity and alignment.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `capacity == 0`
    /// - `alignment` is zero or not a power of two
    /// - `capacity`, rounded up to `alignment`, exceeds `isize::MAX`
    ///
    /// # Aborts
    ///
    /// Aborts the process on allocation failure via `handle_alloc_error`.
    fn new(capacity: usize, alignment: usize) -> Self {
        assert!(capacity > 0, "capacity must be greater than zero");
        let layout = Layout::from_size_align(capacity, alignment).expect("invalid layout");

        // SAFETY: Layout is valid and has non-zero size.
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));

        Self { ptr, layout }
    }

    /// Allocates a new zero-initialized buffer with the given capacity and alignment.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `capacity == 0`
    /// - `alignment` is zero or not a power of two
    /// - `capacity`, rounded up to `alignment`, exceeds `isize::MAX`
    ///
    /// # Aborts
    ///
    /// Aborts the process on allocation failure via `handle_alloc_error`.
    fn new_zeroed(capacity: usize, alignment: usize) -> Self {
        assert!(capacity > 0, "capacity must be greater than zero");
        let layout = Layout::from_size_align(capacity, alignment).expect("invalid layout");

        // SAFETY: Layout is valid and has non-zero size.
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));

        Self { ptr, layout }
    }

    /// Returns the capacity of the buffer.
    #[inline]
    const fn capacity(&self) -> usize {
        self.layout.size()
    }

    /// Returns a raw pointer to the buffer.
    #[inline]
    const fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: ptr was allocated with this layout.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

/// Per-size-class state.
///
/// The freelist stores `Option<AlignedBuffer>` where:
/// - `Some(buf)` = a reusable buffer
/// - `None` = an available slot for creating a new buffer
struct SizeClass {
    /// The buffer size for this class.
    size: usize,
    /// Buffer alignment.
    alignment: usize,
    /// Free list storing either reusable buffers or empty slots.
    freelist: ArrayQueue<Option<AlignedBuffer>>,
    /// Number of buffers currently allocated (out of pool).
    allocated: AtomicUsize,
}

impl SizeClass {
    fn new(size: usize, alignment: usize, max_buffers: usize, prefill: bool) -> Self {
        let freelist = ArrayQueue::new(max_buffers);
        for _ in 0..max_buffers {
            let entry = if prefill {
                Some(AlignedBuffer::new(size, alignment))
            } else {
                None
            };
            let _ = freelist.push(entry);
        }
        Self {
            size,
            alignment,
            freelist,
            allocated: AtomicUsize::new(0),
        }
    }
}

/// Internal allocation result for pooled allocations.
struct Allocation {
    buffer: AlignedBuffer,
    is_new: bool,
}

/// Internal state of the buffer pool.
pub(crate) struct BufferPoolInner {
    config: BufferPoolConfig,
    classes: Vec<SizeClass>,
    metrics: PoolMetrics,
}

impl BufferPoolInner {
    /// Try to allocate a buffer from the given size class.
    ///
    /// If `zero_on_new` is true, newly-created buffers are allocated with
    /// `alloc_zeroed`. Reused buffers are never re-zeroed here.
    fn try_alloc(&self, class_index: usize, zero_on_new: bool) -> Option<Allocation> {
        let class = &self.classes[class_index];
        let label = SizeClassLabel {
            size_class: class.size as u64,
        };

        match class.freelist.pop() {
            Some(Some(buffer)) => {
                // Reuse existing buffer
                class.allocated.fetch_add(1, Ordering::Relaxed);
                self.metrics.allocations_total.get_or_create(&label).inc();
                self.metrics.allocated.get_or_create(&label).inc();
                self.metrics.available.get_or_create(&label).dec();
                Some(Allocation {
                    buffer,
                    is_new: false,
                })
            }
            Some(None) => {
                // Create new buffer (we have a slot)
                class.allocated.fetch_add(1, Ordering::Relaxed);
                self.metrics.allocations_total.get_or_create(&label).inc();
                self.metrics.allocated.get_or_create(&label).inc();
                let buffer = if zero_on_new {
                    AlignedBuffer::new_zeroed(class.size, class.alignment)
                } else {
                    AlignedBuffer::new(class.size, class.alignment)
                };
                Some(Allocation {
                    buffer,
                    is_new: true,
                })
            }
            None => {
                // Pool exhausted (no slots available)
                self.metrics.exhausted_total.get_or_create(&label).inc();
                None
            }
        }
    }

    /// Return a buffer to the pool.
    fn return_buffer(&self, buffer: AlignedBuffer) {
        // Find the class for this buffer size
        if let Some(class_index) = self.config.class_index(buffer.capacity()) {
            let class = &self.classes[class_index];
            let label = SizeClassLabel {
                size_class: class.size as u64,
            };

            class.allocated.fetch_sub(1, Ordering::Relaxed);
            self.metrics.allocated.get_or_create(&label).dec();

            // Try to return to freelist
            match class.freelist.push(Some(buffer)) {
                Ok(()) => {
                    self.metrics.available.get_or_create(&label).inc();
                }
                Err(_buffer) => {
                    // Freelist full, buffer is dropped and deallocated
                }
            }
        }
        // Buffer doesn't match any class (or freelist full) - it's dropped and deallocated
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
/// After calling `Buf::advance()`, the pointer returned by `as_mut_ptr()` may
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
    pub(crate) fn new(config: BufferPoolConfig, registry: &mut Registry) -> Self {
        config.validate();

        let metrics = PoolMetrics::new(registry);

        let mut classes = Vec::with_capacity(config.num_classes());
        for i in 0..config.num_classes() {
            let size = config.class_size(i);
            let class = SizeClass::new(
                size,
                config.alignment.get(),
                config.max_per_class.get(),
                config.prefill,
            );
            classes.push(class);
        }

        // Update available metrics after prefill
        if config.prefill {
            for class in &classes {
                let label = SizeClassLabel {
                    size_class: class.size as u64,
                };
                let available = class.freelist.len() as i64;
                metrics.available.get_or_create(&label).set(available);
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
    /// allocation.
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
        let class_index = self
            .class_index_or_record_oversized(capacity)
            .ok_or(PoolError::Oversized)?;

        let buffer = self
            .inner
            .try_alloc(class_index, false)
            .map(|allocation| allocation.buffer)
            .ok_or(PoolError::Exhausted)?;
        let pooled = PooledBufMut::new(buffer, Arc::downgrade(&self.inner));
        Ok(IoBufMut::from_pooled(pooled))
    }

    /// Allocates a buffer with capacity for at least `capacity` bytes.
    ///
    /// The returned buffer has `len() == 0` and `capacity() >= capacity`,
    /// matching the semantics of [`IoBufMut::with_capacity`] and
    /// `BytesMut::with_capacity`. Use `put_slice` or other `BufMut` methods
    /// to write data to the buffer.
    ///
    /// If the pool can provide a buffer (capacity within limits and pool not
    /// exhausted), returns a pooled buffer that will be returned to the pool
    /// when dropped. Otherwise, falls back to an untracked aligned heap
    /// allocation that is deallocated when dropped.
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
            let buffer = AlignedBuffer::new(size, self.inner.config.alignment.get());
            // Using Weak::new() means the buffer won't be returned to the pool on drop.
            IoBufMut::from_pooled(PooledBufMut::new(buffer, Weak::new()))
        })
    }

    /// Allocates a buffer and sets its readable length to `len` without
    /// initializing bytes.
    ///
    /// Equivalent to `alloc(len)` followed by `set_len(len)`.
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
    /// untracked allocation.
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
        let class_index = self
            .class_index_or_record_oversized(len)
            .ok_or(PoolError::Oversized)?;
        let allocation = self
            .inner
            .try_alloc(class_index, true)
            .ok_or(PoolError::Exhausted)?;

        let mut buf = IoBufMut::from_pooled(PooledBufMut::new(
            allocation.buffer,
            Arc::downgrade(&self.inner),
        ));
        if allocation.is_new {
            // SAFETY: buffer was allocated with alloc_zeroed, so bytes in 0..len are initialized.
            unsafe { buf.set_len(len) };
        } else {
            // Reused buffers may contain old bytes, re-zero requested readable range.
            buf.put_bytes(0, len);
        }
        Ok(buf)
    }

    /// Allocates a zero-initialized buffer with readable length `len`.
    ///
    /// The returned buffer has `len() == len` and `capacity() >= len`.
    ///
    /// If the pool can provide a buffer (len within limits and pool not
    /// exhausted), returns a pooled buffer that will be returned to the pool
    /// when dropped. Otherwise, falls back to an untracked aligned heap
    /// allocation that is deallocated when dropped.
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
            let buffer = AlignedBuffer::new_zeroed(size, self.inner.config.alignment.get());
            let mut buf = IoBufMut::from_pooled(PooledBufMut::new(buffer, Weak::new()));
            // SAFETY: buffer was allocated with alloc_zeroed, so bytes in 0..len are initialized.
            unsafe { buf.set_len(len) };
            buf
        })
    }

    /// Returns the pool configuration.
    pub fn config(&self) -> &BufferPoolConfig {
        &self.inner.config
    }
}

/// Shared pooled allocation.
///
/// On drop, returns the aligned buffer to the pool if tracked.
struct PooledBufInner {
    buffer: ManuallyDrop<AlignedBuffer>,
    pool: Weak<BufferPoolInner>,
}

impl PooledBufInner {
    const fn new(buffer: AlignedBuffer, pool: Weak<BufferPoolInner>) -> Self {
        Self {
            buffer: ManuallyDrop::new(buffer),
            pool,
        }
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.buffer.capacity()
    }
}

impl Drop for PooledBufInner {
    fn drop(&mut self) {
        // SAFETY: Drop is called at most once for this value.
        let buffer = unsafe { ManuallyDrop::take(&mut self.buffer) };
        if let Some(pool) = self.pool.upgrade() {
            pool.return_buffer(buffer);
        }
        // else: buffer is dropped here, which deallocates it
    }
}

/// Immutable, reference-counted view over a pooled allocation.
///
/// Cloning is cheap and shares the same underlying aligned allocation.
///
/// # View Layout
///
/// ```text
/// [0................offset...........offset+len...........capacity]
///  ^                 ^                   ^                    ^
///  |                 |                   |                    |
///  allocation start  first readable      end of readable      allocation end
///                    byte of this view   region for this view
/// ```
///
/// Regions:
/// - `[0..offset)`: not readable from this view
/// - `[offset..offset+len)`: readable bytes for this view
/// - `[offset+len..capacity)`: not readable from this view
///
/// # Invariants
///
/// - `offset <= capacity`
/// - `offset + len <= capacity`
///
/// This representation allows sliced views to preserve their current readable
/// window while still supporting `try_into_mut` when uniquely owned.
#[derive(Clone)]
pub(crate) struct PooledBuf {
    inner: Arc<PooledBufInner>,
    offset: usize,
    len: usize,
}

impl std::fmt::Debug for PooledBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuf")
            .field("offset", &self.offset)
            .field("len", &self.len)
            .field("capacity", &self.inner.capacity())
            .finish()
    }
}

impl PooledBuf {
    /// Returns `true` if this buffer is tracked by a pool.
    ///
    /// Tracked buffers originate from `BufferPool` allocations and are
    /// returned to their pool when dropped.
    ///
    /// Untracked fallback allocations from [`BufferPool::alloc`] return `false`.
    #[inline]
    pub fn is_tracked(&self) -> bool {
        self.inner.pool.strong_count() > 0
    }

    /// Returns a pointer to the first readable byte.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        // SAFETY: offset is always within the underlying allocation.
        unsafe { self.inner.buffer.as_ptr().add(self.offset) }
    }

    /// Returns a slice of this view (zero-copy).
    ///
    /// The range is resolved relative to this view's readable window
    /// (`0..self.len`), not relative to the allocation start.
    ///
    /// Returns `None` for empty ranges, allowing callers to detach from the
    /// underlying pooled allocation.
    pub fn slice(&self, range: impl RangeBounds<usize>) -> Option<Self> {
        let start = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.checked_add(1).expect("range start overflow"),
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&n) => n.checked_add(1).expect("range end overflow"),
            Bound::Excluded(&n) => n,
            Bound::Unbounded => self.len,
        };
        assert!(start <= end, "slice start must be <= end");
        assert!(end <= self.len, "slice out of bounds");

        if start == end {
            return None;
        }

        Some(Self {
            inner: Arc::clone(&self.inner),
            offset: self.offset + start,
            len: end - start,
        })
    }

    /// Try to recover mutable ownership without copying.
    ///
    /// This succeeds only when this is the sole remaining reference to the
    /// underlying pooled allocation (`Arc` strong count is 1).
    ///
    /// On success, the returned mutable buffer preserves the readable bytes and
    /// mutable capacity from this view's current offset to the end of the
    /// allocation. This means uniquely-owned sliced views can also be recovered
    /// as mutable buffers while keeping the same readable window.
    ///
    /// On failure, returns `self` unchanged.
    pub fn try_into_mut(self) -> Result<PooledBufMut, Self> {
        let Self { inner, offset, len } = self;
        match Arc::try_unwrap(inner) {
            // Preserve the existing readable view:
            // - cursor = view start
            // - len = view end
            Ok(inner) => Ok(PooledBufMut {
                inner: ManuallyDrop::new(inner),
                cursor: offset,
                len: offset.checked_add(len).expect("slice end overflow"),
            }),
            Err(inner) => Err(Self { inner, offset, len }),
        }
    }
}

impl AsRef<[u8]> for PooledBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: offset/len are always bounded within the underlying allocation.
        unsafe { std::slice::from_raw_parts(self.inner.buffer.as_ptr().add(self.offset), self.len) }
    }
}

impl Buf for PooledBuf {
    #[inline]
    fn remaining(&self) -> usize {
        self.len
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.as_ref()
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.len, "cannot advance past end of buffer");
        self.offset += cnt;
        self.len -= cnt;
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        assert!(len <= self.len, "copy_to_bytes out of bounds");
        if len == 0 {
            return Bytes::new();
        }
        let slice = Self {
            inner: Arc::clone(&self.inner),
            offset: self.offset,
            len,
        };
        self.advance(len);
        Bytes::from_owner(slice)
    }
}

/// A mutable aligned buffer.
///
/// When dropped, the underlying buffer is returned to the pool if tracked,
/// or deallocated directly if untracked (e.g. fallback allocations).
///
/// # Buffer Layout
///
/// ```text
/// [0................cursor..............len.............raw_capacity]
///  ^                 ^                   ^                 ^
///  |                 |                   |                 |
///  allocation start  read position       write position    allocation end
///                    (consumed prefix)   (initialized)
///
/// Regions:
/// - [0..cursor]:        consumed (via Buf::advance), no longer accessible
/// - [cursor..len]:      readable bytes (as_ref returns this slice)
/// - [len..raw_capacity]: uninitialized, writable via BufMut
/// ```
///
/// # Invariants
///
/// - `cursor <= len <= raw_capacity`
/// - Bytes in `0..len` have been initialized (safe to read)
/// - Bytes in `len..raw_capacity` are uninitialized (write-only via `BufMut`)
///
/// # Computed Values
///
/// - `len()` = readable bytes = `self.len - cursor`
/// - `capacity()` = view capacity = `raw_capacity - cursor` (shrinks after advance)
/// - `remaining_mut()` = writable bytes = `raw_capacity - self.len`
///
/// This matches `BytesMut` semantics.
///
/// # Fixed Capacity
///
/// Unlike `BytesMut`, pooled buffers have **fixed capacity** and do NOT grow
/// automatically. Calling `put_slice()` or other `BufMut` methods that would
/// exceed capacity will panic (per the `BufMut` trait contract).
///
/// Always check `remaining_mut()` before writing variable-length data.
pub(crate) struct PooledBufMut {
    inner: ManuallyDrop<PooledBufInner>,
    /// Read cursor position (for `Buf` trait).
    cursor: usize,
    /// Number of bytes written (initialized).
    len: usize,
}

impl std::fmt::Debug for PooledBufMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBufMut")
            .field("cursor", &self.cursor)
            .field("len", &self.len)
            .field("capacity", &self.capacity())
            .finish()
    }
}

impl PooledBufMut {
    const fn new(buffer: AlignedBuffer, pool: Weak<BufferPoolInner>) -> Self {
        Self {
            inner: ManuallyDrop::new(PooledBufInner::new(buffer, pool)),
            cursor: 0,
            len: 0,
        }
    }

    /// Returns `true` if this buffer is tracked by a pool.
    ///
    /// Tracked buffers originate from `BufferPool` allocations and are
    /// returned to their pool when dropped.
    ///
    /// Untracked fallback allocations from [`BufferPool::alloc`] return `false`.
    #[inline]
    pub fn is_tracked(&self) -> bool {
        self.inner.pool.strong_count() > 0
    }

    /// Returns the number of readable bytes remaining in the buffer.
    ///
    /// This is `len - cursor`, matching `BytesMut` semantics.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len - self.cursor
    }

    /// Returns true if no readable bytes remain.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.cursor == self.len
    }

    /// Returns the number of bytes the buffer can hold without reallocating.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity() - self.cursor
    }

    /// Returns the raw allocation capacity (internal use only).
    #[inline]
    fn raw_capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Returns an unsafe mutable pointer to the buffer's data.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        // SAFETY: cursor is always <= raw capacity
        unsafe { self.inner.buffer.as_ptr().add(self.cursor) }
    }

    /// Sets the length of the buffer (view-relative).
    ///
    /// This will explicitly set the size of the buffer without actually
    /// modifying the data, so it is up to the caller to ensure that the data
    /// has been initialized.
    ///
    /// The `len` parameter is relative to the current view (after any `advance`
    /// calls), matching `BytesMut::set_len` semantics.
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// - All bytes in the range `[cursor, cursor + len)` are initialized
    /// - `len <= capacity()` (where capacity is view-relative)
    #[inline]
    pub const unsafe fn set_len(&mut self, len: usize) {
        self.len = self.cursor + len;
    }

    /// Clears the buffer, removing all data. Existing capacity is preserved.
    #[inline]
    pub const fn clear(&mut self) {
        self.len = self.cursor;
    }

    /// Truncates the buffer to at most `len` readable bytes.
    ///
    /// If `len` is greater than the current readable length, this has no effect.
    /// This operates on readable bytes (after cursor), matching `BytesMut::truncate`
    /// semantics for buffers that have been advanced.
    #[inline]
    pub const fn truncate(&mut self, len: usize) {
        if len < self.len() {
            self.len = self.cursor + len;
        }
    }

    /// Freezes the buffer into an immutable `IoBuf`.
    ///
    /// Only the readable portion (`cursor..len`) is included in the result.
    /// The underlying buffer will be returned to the pool when all references
    /// to the `IoBuf` (including slices) are dropped.
    pub fn freeze(self) -> IoBuf {
        // Wrap self in ManuallyDrop first to prevent Drop from running
        // if any subsequent code panics.
        let mut me = ManuallyDrop::new(self);
        // SAFETY: me is wrapped in ManuallyDrop so its Drop impl won't run.
        // ManuallyDrop::take moves the inner value out, leaving the wrapper empty.
        let inner = unsafe { ManuallyDrop::take(&mut me.inner) };
        IoBuf::from_pooled(PooledBuf {
            inner: Arc::new(inner),
            offset: me.cursor,
            len: me.len - me.cursor,
        })
    }
}

impl AsRef<[u8]> for PooledBufMut {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: bytes from cursor..len have been initialized.
        unsafe {
            std::slice::from_raw_parts(self.inner.buffer.as_ptr().add(self.cursor), self.len())
        }
    }
}

impl AsMut<[u8]> for PooledBufMut {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        let len = self.len();
        // SAFETY: bytes from cursor..len have been initialized.
        unsafe { std::slice::from_raw_parts_mut(self.inner.buffer.as_ptr().add(self.cursor), len) }
    }
}

impl Drop for PooledBufMut {
    fn drop(&mut self) {
        // SAFETY: Drop is only called once. freeze() wraps self in ManuallyDrop
        // to prevent this Drop impl from running after ownership is transferred.
        unsafe { ManuallyDrop::drop(&mut self.inner) };
    }
}

impl Buf for PooledBufMut {
    #[inline]
    fn remaining(&self) -> usize {
        self.len - self.cursor
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        // SAFETY: bytes from cursor..len have been initialized.
        unsafe {
            std::slice::from_raw_parts(
                self.inner.buffer.as_ptr().add(self.cursor),
                self.len - self.cursor,
            )
        }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        let remaining = self.len - self.cursor;
        assert!(cnt <= remaining, "cannot advance past end of buffer");
        self.cursor += cnt;
    }
}

// SAFETY: BufMut implementation for PooledBufMut.
// - `remaining_mut()` reports bytes available for writing (raw_capacity - len)
// - `chunk_mut()` returns uninitialized memory from len to raw_capacity
// - `advance_mut()` advances len within bounds
unsafe impl BufMut for PooledBufMut {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.raw_capacity() - self.len
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        assert!(
            cnt <= self.remaining_mut(),
            "cannot advance past end of buffer"
        );
        self.len += cnt;
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        let raw_cap = self.raw_capacity();
        let len = self.len;
        // SAFETY: We have exclusive access and the slice is within raw capacity.
        unsafe {
            let ptr = self.inner.buffer.as_ptr().add(len);
            bytes::buf::UninitSlice::from_raw_parts_mut(ptr, raw_cap - len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IoBufs;
    use bytes::BytesMut;
    use std::{sync::mpsc, thread};

    fn test_registry() -> Registry {
        Registry::default()
    }

    /// Creates a test config with page alignment.
    fn test_config(min_size: usize, max_size: usize, max_per_class: usize) -> BufferPoolConfig {
        BufferPoolConfig {
            min_size: NZUsize!(min_size),
            max_size: NZUsize!(max_size),
            max_per_class: NZUsize!(max_per_class),
            prefill: false,
            alignment: NZUsize!(page_size()),
        }
    }

    #[test]
    fn test_page_size() {
        let size = page_size();
        assert!(size >= 4096);
        assert!(size.is_power_of_two());
    }

    #[test]
    fn test_aligned_buffer() {
        let page = page_size();
        let buf = AlignedBuffer::new(4096, page);
        assert_eq!(buf.capacity(), 4096);
        assert!((buf.as_ptr() as usize).is_multiple_of(page));

        // Test with cache-line alignment
        let cache_line = cache_line_size();
        let buf2 = AlignedBuffer::new(4096, cache_line);
        assert_eq!(buf2.capacity(), 4096);
        assert!((buf2.as_ptr() as usize).is_multiple_of(cache_line));
    }

    #[test]
    #[should_panic(expected = "capacity must be greater than zero")]
    fn test_aligned_buffer_zero_capacity_panics() {
        let _ = AlignedBuffer::new(0, page_size());
    }

    #[test]
    #[should_panic(expected = "capacity must be greater than zero")]
    fn test_aligned_buffer_zeroed_zero_capacity_panics() {
        let _ = AlignedBuffer::new_zeroed(0, page_size());
    }

    #[test]
    fn test_config_validation() {
        let page = page_size();
        let config = test_config(page, page * 4, 10);
        config.validate();
    }

    #[test]
    #[should_panic(expected = "min_size must be a power of two")]
    fn test_config_invalid_min_size() {
        let config = BufferPoolConfig {
            min_size: NZUsize!(3000),
            max_size: NZUsize!(8192),
            max_per_class: NZUsize!(10),
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
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 2), &mut registry);

        // Allocate a buffer - returns buffer with len=0, capacity >= requested
        let buf = pool.try_alloc(100).unwrap();
        assert!(buf.capacity() >= page);
        assert_eq!(buf.len(), 0);

        // Drop returns to pool
        drop(buf);

        // Can allocate again
        let buf2 = pool.try_alloc(100).unwrap();
        assert!(buf2.capacity() >= page);
        assert_eq!(buf2.len(), 0);
    }

    #[test]
    fn test_alloc_len_sets_len() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 2), &mut registry);

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
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 2), &mut registry);

        let buf = pool.alloc_zeroed(100);
        assert_eq!(buf.len(), 100);
        assert!(buf.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_try_alloc_zeroed_sets_len_and_zeros() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 2), &mut registry);

        let buf = pool.try_alloc_zeroed(100).unwrap();
        assert!(buf.is_pooled());
        assert_eq!(buf.len(), 100);
        assert!(buf.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_alloc_zeroed_fallback_uses_untracked_zeroed_buffer() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 1), &mut registry);

        // Exhaust pooled capacity for this class.
        let _pooled = pool.try_alloc(100).unwrap();

        let buf = pool.alloc_zeroed(100);
        assert!(!buf.is_pooled());
        assert_eq!(buf.len(), 100);
        assert!(buf.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_alloc_zeroed_reuses_dirty_pooled_buffer() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 1), &mut registry);

        let mut first = pool.alloc_zeroed(100);
        assert!(first.is_pooled());
        assert!(first.as_ref().iter().all(|&b| b == 0));

        // Dirty the buffer before returning it to the pool.
        first.as_mut().fill(0xAB);
        drop(first);

        let second = pool.alloc_zeroed(100);
        assert!(second.is_pooled());
        assert_eq!(second.len(), 100);
        assert!(second.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_pool_exhaustion() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        // Allocate max buffers
        let _buf1 = pool.try_alloc(100).expect("first alloc should succeed");
        let _buf2 = pool.try_alloc(100).expect("second alloc should succeed");

        // Third allocation should fail
        assert!(pool.try_alloc(100).is_err());
    }

    #[test]
    fn test_pool_oversized() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 2, 10), &mut registry);

        // Request larger than max_size
        assert!(pool.try_alloc(page * 4).is_err());
    }

    #[test]
    fn test_pool_size_classes() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 10), &mut registry);

        // Small request gets smallest class
        let buf1 = pool.try_alloc(100).unwrap();
        assert_eq!(buf1.capacity(), page);

        // Larger request gets appropriate class
        let buf2 = pool.try_alloc(page + 1).unwrap();
        assert_eq!(buf2.capacity(), page * 2);

        let buf3 = pool.try_alloc(page * 3).unwrap();
        assert_eq!(buf3.capacity(), page * 4);
    }

    #[test]
    fn test_pooled_buf_mut_freeze() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        // Allocate and initialize a buffer
        let mut buf = pool.try_alloc(11).unwrap();
        buf.put_slice(&[0u8; 11]);
        assert_eq!(buf.len(), 11);

        // Write some data
        buf.as_mut()[..5].copy_from_slice(&[1, 2, 3, 4, 5]);

        // Freeze preserves the content
        let iobuf = buf.freeze();
        assert_eq!(iobuf.len(), 11);
        assert_eq!(&iobuf.as_ref()[..5], &[1, 2, 3, 4, 5]);

        // IoBuf can be sliced
        let slice = iobuf.slice(0..5);
        assert_eq!(slice.len(), 5);
    }

    #[test]
    fn test_prefill() {
        let page = NZUsize!(page_size());
        let mut registry = test_registry();
        let pool = BufferPool::new(
            BufferPoolConfig {
                min_size: page,
                max_size: page,
                max_per_class: NZUsize!(5),
                prefill: true,
                alignment: page,
            },
            &mut registry,
        );

        // Should be able to allocate max_per_class buffers immediately
        let mut bufs = Vec::new();
        for _ in 0..5 {
            bufs.push(pool.try_alloc(100).expect("alloc should succeed"));
        }

        // Next allocation should fail
        assert!(pool.try_alloc(100).is_err());
    }

    #[test]
    fn test_config_for_network() {
        let config = BufferPoolConfig::for_network();
        config.validate();
        assert_eq!(config.min_size.get(), cache_line_size());
        assert_eq!(config.max_size.get(), 64 * 1024);
        assert_eq!(config.max_per_class.get(), 4096);
        assert!(!config.prefill);
        assert_eq!(config.alignment.get(), cache_line_size());
    }

    #[test]
    fn test_config_for_storage() {
        let config = BufferPoolConfig::for_storage();
        config.validate();
        assert_eq!(config.min_size.get(), page_size());
        assert_eq!(config.max_size.get(), 64 * 1024);
        assert_eq!(config.max_per_class.get(), 32);
        assert!(!config.prefill);
        assert_eq!(config.alignment.get(), page_size());
    }

    #[test]
    fn test_config_builders() {
        let page = NZUsize!(page_size());
        let config = BufferPoolConfig::for_storage()
            .with_max_per_class(NZUsize!(64))
            .with_prefill(true)
            .with_min_size(page)
            .with_max_size(NZUsize!(128 * 1024));

        config.validate();
        assert_eq!(config.min_size, page);
        assert_eq!(config.max_size.get(), 128 * 1024);
        assert_eq!(config.max_per_class.get(), 64);
        assert!(config.prefill);

        // Storage profile alignment stays page-sized unless explicitly changed.
        assert_eq!(config.alignment.get(), page_size());

        // Alignment can be tuned explicitly as long as min_size is also adjusted.
        let aligned = BufferPoolConfig::for_network()
            .with_alignment(NZUsize!(256))
            .with_min_size(NZUsize!(256));
        aligned.validate();
        assert_eq!(aligned.alignment.get(), 256);
        assert_eq!(aligned.min_size.get(), 256);
    }

    #[test]
    fn test_config_with_budget_bytes() {
        // Classes: 4, 8, 16 (sum = 28). Budget 280 => max_per_class = 10.
        let config = BufferPoolConfig {
            min_size: NZUsize!(4),
            max_size: NZUsize!(16),
            max_per_class: NZUsize!(1),
            prefill: false,
            alignment: NZUsize!(4),
        }
        .with_budget_bytes(NZUsize!(280));
        assert_eq!(config.max_per_class.get(), 10);

        // Budget 10 rounds up to one buffer per class.
        let small_budget = BufferPoolConfig {
            min_size: NZUsize!(4),
            max_size: NZUsize!(16),
            max_per_class: NZUsize!(1),
            prefill: false,
            alignment: NZUsize!(4),
        }
        .with_budget_bytes(NZUsize!(10));
        assert_eq!(small_budget.max_per_class.get(), 1);
    }

    /// Helper to get the number of allocated buffers for a size class.
    fn get_allocated(pool: &BufferPool, size: usize) -> usize {
        let class_index = pool.inner.config.class_index(size).unwrap();
        pool.inner.classes[class_index]
            .allocated
            .load(Ordering::Relaxed)
    }

    /// Helper to get the number of available buffers in freelist for a size class.
    fn get_available(pool: &BufferPool, size: usize) -> i64 {
        let class_index = pool.inner.config.class_index(size).unwrap();
        let label = SizeClassLabel {
            size_class: pool.inner.classes[class_index].size as u64,
        };
        pool.inner.metrics.available.get_or_create(&label).get()
    }

    #[test]
    fn test_freeze_returns_buffer_to_pool() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        // Initially: 0 allocated, 0 available
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 0);

        // Allocate and freeze
        let buf = pool.try_alloc(100).unwrap();
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
    fn test_cloned_iobuf_returns_buffer_when_all_dropped() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let buf = pool.try_alloc(100).unwrap();
        let iobuf = buf.freeze();

        // Clone the IoBuf multiple times (this clones the pooled view via Arc).
        let clone1 = iobuf.clone();
        let clone2 = iobuf.clone();
        let clone3 = iobuf.clone();

        assert_eq!(get_allocated(&pool, page), 1);

        // Drop original and some clones - buffer should NOT return yet
        drop(iobuf);
        drop(clone1);
        assert_eq!(get_allocated(&pool, page), 1);
        assert_eq!(get_available(&pool, page), 0);

        // Drop remaining clones - buffer should return
        drop(clone2);
        assert_eq!(get_allocated(&pool, page), 1); // Still held by clone3

        drop(clone3);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_slice_holds_buffer_reference() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0u8; 100]);
        let iobuf = buf.freeze();

        // Create a slice - this should hold a reference to the underlying buffer
        let slice = iobuf.slice(10..50);

        // Drop original - slice should keep buffer alive
        drop(iobuf);
        assert_eq!(get_allocated(&pool, page), 1);
        assert_eq!(get_available(&pool, page), 0);

        // Drop slice - buffer should return
        drop(slice);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_empty_slice_does_not_hold_buffer_reference() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0u8; 100]);
        let iobuf = buf.freeze();

        // Empty slices should not retain the original backing allocation.
        let empty = iobuf.slice(10..10);
        assert!(empty.is_empty());

        drop(iobuf);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_copy_to_bytes_on_pooled_buffer() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0x42u8; 100]);
        let mut iobuf = buf.freeze();

        // copy_to_bytes should create a slice sharing the same buffer
        let extracted = iobuf.copy_to_bytes(50);
        assert_eq!(extracted.len(), 50);
        assert!(extracted.iter().all(|&b| b == 0x42));

        // Both should hold references
        assert_eq!(get_allocated(&pool, page), 1);

        // Drop original
        drop(iobuf);
        assert_eq!(get_allocated(&pool, page), 1); // extracted holds it

        // Drop extracted
        drop(extracted);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_copy_to_bytes_zero_len_on_pooled_buffer() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0x42u8; 100]);
        let mut iobuf = buf.freeze();

        // copy_to_bytes(0) should return an empty Bytes without retaining the pooled owner.
        let extracted = iobuf.copy_to_bytes(0);
        assert!(extracted.is_empty());
        assert_eq!(iobuf.len(), 100);
        assert_eq!(get_allocated(&pool, page), 1);

        // Dropping the original should return the buffer immediately.
        drop(iobuf);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);

        drop(extracted);
    }

    #[test]
    fn test_copy_to_bytes_full_drain_releases_pool_from_source() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0xAB; 100]);
        let mut iobuf = buf.freeze();
        assert_eq!(get_allocated(&pool, page), 1);

        // Full drain of remaining data.
        let extracted = iobuf.copy_to_bytes(100);
        assert_eq!(&extracted[..], &[0xAB; 100]);
        assert_eq!(iobuf.remaining(), 0);

        // Drained source should be detached and not pin the pooled allocation.
        drop(iobuf);
        assert_eq!(get_allocated(&pool, page), 1);

        drop(extracted);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_copy_to_bytes_partial_then_full_drain_releases_pool_from_source() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0xCD; 100]);
        let mut iobuf = buf.freeze();

        // Partial drain.
        let partial = iobuf.copy_to_bytes(30);
        assert_eq!(&partial[..], &[0xCD; 30]);
        assert_eq!(iobuf.remaining(), 70);
        assert_eq!(get_allocated(&pool, page), 1);

        // Full drain of remainder.
        let rest = iobuf.copy_to_bytes(70);
        assert_eq!(&rest[..], &[0xCD; 70]);
        assert_eq!(iobuf.remaining(), 0);

        // Source should be detached after full drain.
        drop(iobuf);
        assert_eq!(get_allocated(&pool, page), 1);

        // Both extracted views still share the allocation.
        drop(partial);
        assert_eq!(get_allocated(&pool, page), 1);

        drop(rest);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_copy_to_bytes_zero_len_on_empty_pooled_buffer_does_not_transfer_owner() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0xEF; 100]);
        let mut iobuf = buf.freeze();

        // Drain to empty first.
        let full = iobuf.copy_to_bytes(100);
        assert_eq!(iobuf.remaining(), 0);
        assert_eq!(get_allocated(&pool, page), 1);

        // Zero-length copy on already-empty source should not transfer pooled ownership.
        let empty = iobuf.copy_to_bytes(0);
        assert!(empty.is_empty());
        drop(empty);

        // Source is already detached after the full-drain path.
        drop(iobuf);
        assert_eq!(get_allocated(&pool, page), 1);

        drop(full);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_concurrent_clones_and_drops() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 4), &mut registry);

        // Simulate the pattern in Messenger::content where we clone for multiple recipients
        for _ in 0..100 {
            let buf = pool.try_alloc(100).unwrap();
            let iobuf = buf.freeze();

            // Simulate sending to 10 recipients (clone for each)
            let clones: Vec<_> = (0..10).map(|_| iobuf.clone()).collect();
            drop(iobuf);

            // Drop clones one by one
            for clone in clones {
                drop(clone);
            }
        }

        // All buffers should be returned
        assert_eq!(get_allocated(&pool, page), 0);
    }

    #[test]
    fn test_iobuf_to_iobufmut_conversion_reuses_pool_for_non_full_unique_view() {
        // IoBuf -> IoBufMut should recover pooled ownership for unique non-full views.
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let buf = pool.try_alloc(100).unwrap();
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
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.try_alloc(page).unwrap();
        buf.put_slice(&vec![0xEE; page]);
        let iobuf = buf.freeze();

        let iobufmut: IoBufMut = iobuf.into();
        assert_eq!(iobufmut.len(), page);
        assert!(iobufmut.as_ref().iter().all(|&b| b == 0xEE));
        assert_eq!(get_allocated(&pool, page), 1);
        assert_eq!(get_available(&pool, page), 0);

        drop(iobufmut);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_iobuf_try_into_mut_recycles_full_unique_view() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.try_alloc(page).unwrap();
        buf.put_slice(&vec![0xAB; page]);
        let iobuf = buf.freeze();
        assert_eq!(get_allocated(&pool, page), 1);

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
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

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
    fn test_stream_send_pattern() {
        // Simulates what stream::Sender::send does:
        // 1. Takes impl Into<IoBufs>
        // 2. Allocates encryption buffer from pool
        // 3. Copies plaintext into encryption buffer
        // 4. Encrypts in place
        // 5. Freezes and sends
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 4), &mut registry);

        for _ in 0..100 {
            // Incoming data (could be IoBuf or IoBufMut)
            let mut incoming = pool.try_alloc(100).unwrap();
            incoming.put_slice(&[0x42u8; 100]);
            let incoming_iobuf = incoming.freeze();

            // Convert to IoBufs (what send() does)
            let mut bufs: IoBufs = incoming_iobuf.into();
            let plaintext_len = bufs.remaining();

            // Allocate encryption buffer with capacity (no init needed, we write to it)
            let ciphertext_len = plaintext_len + 16; // +16 for tag
            let mut encryption_buf = pool.try_alloc(ciphertext_len).unwrap();
            // SAFETY: We fill the entire buffer before reading
            unsafe { encryption_buf.set_len(ciphertext_len) };

            // Copy plaintext into encryption buffer
            let mut offset = 0;
            while bufs.has_remaining() {
                let chunk = bufs.chunk();
                let chunk_len = chunk.len();
                encryption_buf.as_mut()[offset..offset + chunk_len].copy_from_slice(chunk);
                offset += chunk_len;
                bufs.advance(chunk_len);
            }

            // At this point, bufs (which holds the incoming IoBuf) should be fully consumed
            // but the underlying buffer is still referenced until bufs is dropped
            drop(bufs);

            // Simulate encryption (just modify in place)
            encryption_buf.as_mut()[plaintext_len..].fill(0xAA);

            // Freeze and "send"
            let ciphertext = encryption_buf.freeze();

            // Simulate network send completing
            drop(ciphertext);
        }

        // All buffers should be returned
        assert_eq!(get_allocated(&pool, page), 0);
    }

    #[test]
    fn test_multithreaded_alloc_freeze_return() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = Arc::new(BufferPool::new(test_config(page, page, 100), &mut registry));

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
                    let buf = pool.try_alloc(100).unwrap();
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

        // All buffers should be returned
        let class_index = pool.inner.config.class_index(page).unwrap();
        let allocated = pool.inner.classes[class_index]
            .allocated
            .load(Ordering::Relaxed);
        assert_eq!(
            allocated, 0,
            "all buffers should be returned after multithreaded test"
        );
    }

    #[test]
    fn test_cross_thread_buffer_return() {
        // Allocate on one thread, freeze, send to another thread, drop there
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 100), &mut registry);

        let (tx, rx) = mpsc::channel();

        // Allocate and freeze on main thread
        for _ in 0..50 {
            let buf = pool.try_alloc(100).unwrap();
            let iobuf = buf.freeze();
            tx.send(iobuf).unwrap();
        }
        drop(tx);

        // Receive and drop on another thread
        let handle = thread::spawn(move || {
            while let Ok(iobuf) = rx.recv() {
                drop(iobuf);
            }
        });

        handle.join().unwrap();

        // All buffers should be returned
        assert_eq!(get_allocated(&pool, page), 0);
    }

    #[test]
    fn test_pool_dropped_before_buffer() {
        // What happens if the pool is dropped while buffers are still in use?
        // The Weak reference should fail to upgrade, and the buffer should just be deallocated.

        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0u8; 100]);
        let iobuf = buf.freeze();

        // Drop the pool while buffer is still alive
        drop(pool);

        // Buffer should still be usable
        assert_eq!(iobuf.len(), 100);

        // Dropping the buffer should not panic (Weak upgrade fails, buffer is deallocated)
        drop(iobuf);
        // No assertion here - we just want to make sure it doesn't panic
    }

    /// Verify pooled IoBuf matches Bytes semantics for Buf trait methods.
    #[test]
    fn test_bytes_parity_iobuf_buf_trait() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let data: Vec<u8> = (0..100u8).collect();

        let mut pooled_mut = pool.try_alloc(data.len()).unwrap();
        pooled_mut.put_slice(&data);
        let mut pooled = pooled_mut.freeze();
        let mut bytes = Bytes::from(data);

        // remaining() + chunk()
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // advance()
        Buf::advance(&mut bytes, 13);
        Buf::advance(&mut pooled, 13);
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // copy_to_bytes(0)
        let bytes_zero = Buf::copy_to_bytes(&mut bytes, 0);
        let pooled_zero = Buf::copy_to_bytes(&mut pooled, 0);
        assert_eq!(bytes_zero, pooled_zero);
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // copy_to_bytes(n)
        let bytes_mid = Buf::copy_to_bytes(&mut bytes, 17);
        let pooled_mid = Buf::copy_to_bytes(&mut pooled, 17);
        assert_eq!(bytes_mid, pooled_mid);
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // copy_to_bytes(remaining)
        let remaining = Buf::remaining(&bytes);
        let bytes_rest = Buf::copy_to_bytes(&mut bytes, remaining);
        let pooled_rest = Buf::copy_to_bytes(&mut pooled, remaining);
        assert_eq!(bytes_rest, pooled_rest);
        assert_eq!(Buf::remaining(&bytes), 0);
        assert_eq!(Buf::remaining(&pooled), 0);
        assert!(!Buf::has_remaining(&bytes));
        assert!(!Buf::has_remaining(&pooled));
    }

    /// Verify pooled IoBuf slice behavior matches Bytes for content semantics.
    #[test]
    fn test_bytes_parity_iobuf_slice() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let data: Vec<u8> = (0..32u8).collect();
        let mut pooled_mut = pool.try_alloc(data.len()).unwrap();
        pooled_mut.put_slice(&data);
        let pooled = pooled_mut.freeze();
        let bytes = Bytes::from(data);

        assert_eq!(pooled.slice(..5).as_ref(), bytes.slice(..5).as_ref());
        assert_eq!(pooled.slice(6..).as_ref(), bytes.slice(6..).as_ref());
        assert_eq!(pooled.slice(3..8).as_ref(), bytes.slice(3..8).as_ref());
        assert_eq!(pooled.slice(..=7).as_ref(), bytes.slice(..=7).as_ref());
        assert_eq!(pooled.slice(10..10).as_ref(), bytes.slice(10..10).as_ref());
    }

    /// Verify PooledBufMut matches BytesMut semantics for Buf trait.
    #[test]
    fn test_bytesmut_parity_buf_trait() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let mut bytes = BytesMut::with_capacity(100);
        bytes.put_slice(&[0xAAu8; 50]);

        let mut pooled = pool.try_alloc(100).unwrap();
        pooled.put_slice(&[0xAAu8; 50]);

        // remaining()
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));

        // chunk()
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // advance()
        Buf::advance(&mut bytes, 10);
        Buf::advance(&mut pooled, 10);
        assert_eq!(Buf::remaining(&bytes), Buf::remaining(&pooled));
        assert_eq!(Buf::chunk(&bytes), Buf::chunk(&pooled));

        // advance to end
        let remaining = Buf::remaining(&bytes);
        Buf::advance(&mut bytes, remaining);
        Buf::advance(&mut pooled, remaining);
        assert_eq!(Buf::remaining(&bytes), 0);
        assert_eq!(Buf::remaining(&pooled), 0);
        assert!(!Buf::has_remaining(&bytes));
        assert!(!Buf::has_remaining(&pooled));
    }

    /// Verify PooledBufMut matches BytesMut semantics for BufMut trait.
    #[test]
    fn test_bytesmut_parity_bufmut_trait() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let mut bytes = BytesMut::with_capacity(100);
        let mut pooled = pool.try_alloc(100).unwrap();

        // remaining_mut()
        assert!(BufMut::remaining_mut(&bytes) >= 100);
        assert!(BufMut::remaining_mut(&pooled) >= 100);

        // put_slice()
        BufMut::put_slice(&mut bytes, b"hello");
        BufMut::put_slice(&mut pooled, b"hello");
        assert_eq!(bytes.as_ref(), pooled.as_ref());

        // put_u8()
        BufMut::put_u8(&mut bytes, 0x42);
        BufMut::put_u8(&mut pooled, 0x42);
        assert_eq!(bytes.as_ref(), pooled.as_ref());

        // chunk_mut() - verify we can write to it
        let bytes_chunk = BufMut::chunk_mut(&mut bytes);
        let pooled_chunk = BufMut::chunk_mut(&mut pooled);
        assert!(bytes_chunk.len() > 0);
        assert!(pooled_chunk.len() > 0);
    }

    /// Verify truncate works correctly after advance.
    #[test]
    fn test_bytesmut_parity_truncate_after_advance() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let mut bytes = BytesMut::with_capacity(100);
        bytes.put_slice(&[0xAAu8; 50]);
        Buf::advance(&mut bytes, 10);

        let mut pooled = pool.try_alloc(100).unwrap();
        pooled.put_slice(&[0xAAu8; 50]);
        Buf::advance(&mut pooled, 10);

        // Both should have 40 bytes remaining
        assert_eq!(bytes.len(), 40);
        assert_eq!(pooled.len(), 40);

        // Truncate to 20 readable bytes
        bytes.truncate(20);
        pooled.truncate(20);

        assert_eq!(bytes.len(), pooled.len(), "len after truncate");
        assert_eq!(bytes.as_ref(), pooled.as_ref(), "content after truncate");
    }

    /// Verify clear works correctly after advance.
    #[test]
    fn test_bytesmut_parity_clear_after_advance() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let mut bytes = BytesMut::with_capacity(100);
        bytes.put_slice(&[0xAAu8; 50]);
        Buf::advance(&mut bytes, 10);

        let mut pooled = pool.try_alloc(100).unwrap();
        pooled.put_slice(&[0xAAu8; 50]);
        Buf::advance(&mut pooled, 10);

        bytes.clear();
        pooled.clear();

        assert_eq!(bytes.len(), 0);
        assert_eq!(pooled.len(), 0);
        assert!(bytes.is_empty());
        assert!(pooled.is_empty());
    }

    /// Test pool exhaustion and recovery.
    #[test]
    fn test_pool_exhaustion_and_recovery() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 3), &mut registry);

        // Exhaust the pool
        let buf1 = pool.try_alloc(100).expect("first alloc");
        let buf2 = pool.try_alloc(100).expect("second alloc");
        let buf3 = pool.try_alloc(100).expect("third alloc");
        assert!(pool.try_alloc(100).is_err(), "pool should be exhausted");

        // Return one buffer
        drop(buf1);

        // Should be able to allocate again
        let buf4 = pool.try_alloc(100).expect("alloc after return");
        assert!(pool.try_alloc(100).is_err(), "pool exhausted again");

        // Return all and verify freelist reuse
        drop(buf2);
        drop(buf3);
        drop(buf4);

        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 3);

        // Allocate again - should reuse from freelist
        let _buf5 = pool.try_alloc(100).expect("reuse from freelist");
        assert_eq!(get_available(&pool, page), 2);
    }

    /// Test try_alloc error variants.
    #[test]
    fn test_try_alloc_errors() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        // Oversized request
        let result = pool.try_alloc(page * 10);
        assert_eq!(result.unwrap_err(), PoolError::Oversized);

        // Exhaust pool
        let _buf1 = pool.try_alloc(100).unwrap();
        let _buf2 = pool.try_alloc(100).unwrap();
        let result = pool.try_alloc(100);
        assert_eq!(result.unwrap_err(), PoolError::Exhausted);
    }

    #[test]
    fn test_try_alloc_zeroed_errors() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        // Oversized request
        let result = pool.try_alloc_zeroed(page * 10);
        assert_eq!(result.unwrap_err(), PoolError::Oversized);

        // Exhaust pool
        let _buf1 = pool.try_alloc_zeroed(100).unwrap();
        let _buf2 = pool.try_alloc_zeroed(100).unwrap();
        let result = pool.try_alloc_zeroed(100);
        assert_eq!(result.unwrap_err(), PoolError::Exhausted);
    }

    /// Test fallback allocation when pool is exhausted or oversized.
    #[test]
    fn test_fallback_allocation() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        // Exhaust the pool
        let buf1 = pool.try_alloc(100).unwrap();
        let buf2 = pool.try_alloc(100).unwrap();
        assert!(buf1.is_pooled());
        assert!(buf2.is_pooled());

        // Fallback via alloc() when exhausted - still aligned, but untracked
        let mut fallback_exhausted = pool.alloc(100);
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

    /// Test is_pooled method.
    #[test]
    fn test_is_pooled() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let pooled = pool.try_alloc(100).unwrap();
        assert!(pooled.is_pooled());

        let owned = IoBufMut::with_capacity(100);
        assert!(!owned.is_pooled());
    }

    #[test]
    fn test_iobuf_is_pooled() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let pooled = pool.try_alloc(100).unwrap().freeze();
        assert!(pooled.is_pooled());

        // Oversized alloc uses untracked fallback allocation.
        let fallback = pool.alloc(page * 10).freeze();
        assert!(!fallback.is_pooled());

        let bytes = IoBuf::copy_from_slice(b"hello");
        assert!(!bytes.is_pooled());
    }

    #[test]
    fn test_bytesmut_parity_capacity_after_advance() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 10), &mut registry);

        let mut bytes = BytesMut::with_capacity(page);
        bytes.put_slice(&[0xAAu8; 50]);

        let mut pooled = pool.try_alloc(page).unwrap();
        pooled.put_slice(&[0xAAu8; 50]);

        // Before advance
        assert_eq!(bytes.len(), pooled.len(), "len before advance");

        Buf::advance(&mut bytes, 20);
        Buf::advance(&mut pooled, 20);

        // After advance: capacity shrinks, len shrinks
        assert_eq!(bytes.len(), pooled.len(), "len after advance");
        assert_eq!(
            bytes.capacity(),
            pooled.capacity(),
            "capacity after advance"
        );
    }

    #[test]
    fn test_bytesmut_parity_set_len_after_advance() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 10), &mut registry);

        let mut bytes = BytesMut::with_capacity(page);
        bytes.resize(50, 0xBB);
        Buf::advance(&mut bytes, 20);

        let mut pooled = pool.try_alloc(page).unwrap();
        pooled.put_slice(&[0xBB; 50]);
        Buf::advance(&mut pooled, 20);

        // After put_slice(50) and advance(20): cursor=20, len=50, readable=30 bytes (20..50)
        // set_len(25) shrinks readable region to 25 bytes (20..45), which is within initialized range
        // SAFETY: We're shrinking the readable region, all bytes in range are initialized.
        unsafe {
            bytes.set_len(25);
            pooled.set_len(25);
        }

        assert_eq!(bytes.len(), pooled.len(), "len after set_len");
        assert_eq!(bytes.as_ref(), pooled.as_ref(), "content after set_len");
    }

    #[test]
    fn test_bytesmut_parity_clear_preserves_view() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 10), &mut registry);

        let mut bytes = BytesMut::with_capacity(page);
        bytes.resize(50, 0xCC);
        Buf::advance(&mut bytes, 20);
        let cap_before_clear = bytes.capacity();
        bytes.clear();

        let mut pooled = pool.try_alloc(page).unwrap();
        pooled.put_slice(&[0xCC; 50]);
        Buf::advance(&mut pooled, 20);
        let pooled_cap_before = pooled.capacity();
        pooled.clear();

        // clear() sets len to 0 but preserves capacity (doesn't resurrect prefix)
        assert_eq!(bytes.len(), pooled.len(), "len after clear");
        assert_eq!(bytes.capacity(), cap_before_clear, "bytes cap unchanged");
        assert_eq!(pooled.capacity(), pooled_cap_before, "pooled cap unchanged");
    }

    #[test]
    fn test_bytesmut_parity_put_after_advance() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 10), &mut registry);

        let mut bytes = BytesMut::with_capacity(100);
        bytes.resize(30, 0xAA);
        Buf::advance(&mut bytes, 10);
        bytes.put_slice(&[0xBB; 10]);

        let mut pooled = pool.try_alloc(100).unwrap();
        pooled.put_slice(&[0xAA; 30]);
        Buf::advance(&mut pooled, 10);
        pooled.put_slice(&[0xBB; 10]);

        assert_eq!(bytes.as_ref(), pooled.as_ref(), "content after put_slice");
    }

    #[test]
    fn test_buffer_alignment() {
        let page = page_size();
        let cache_line = cache_line_size();
        let mut registry = test_registry();

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
        let storage_buffer_pool = BufferPool::new(storage_config, &mut registry);
        let mut buf = storage_buffer_pool.try_alloc(100).unwrap();
        assert_eq!(
            buf.as_mut_ptr() as usize % page,
            0,
            "storage buffer not page-aligned"
        );

        // Network preset - cache-line aligned
        let network_buffer_pool = BufferPool::new(network_config, &mut registry);
        let mut buf = network_buffer_pool.try_alloc(100).unwrap();
        assert_eq!(
            buf.as_mut_ptr() as usize % cache_line,
            0,
            "network buffer not cache-line aligned"
        );
    }

    #[test]
    fn test_freeze_after_advance_to_end() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0x42; 100]);
        Buf::advance(&mut buf, 100);

        let frozen = buf.freeze();
        assert!(frozen.is_empty());
    }

    #[test]
    fn test_zero_capacity_allocation() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let buf = pool.try_alloc(0).expect("zero capacity should succeed");
        assert_eq!(buf.capacity(), page);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_exact_max_size_allocation() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let buf = pool.try_alloc(page).expect("exact max size should succeed");
        assert_eq!(buf.capacity(), page);
    }

    #[test]
    fn test_freeze_after_partial_advance_mut() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        // Write 50 bytes of initialized data
        buf.put_slice(&[0xAA; 50]);
        // Consume 20 bytes via Buf
        Buf::advance(&mut buf, 20);
        // Freeze should only contain 30 bytes
        let frozen = buf.freeze();
        assert_eq!(frozen.len(), 30);
        assert_eq!(frozen.as_ref(), &[0xAA; 30]);
    }

    #[test]
    fn test_interleaved_advance_and_write() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(b"hello");
        Buf::advance(&mut buf, 2);
        buf.put_slice(b"world");
        assert_eq!(buf.as_ref(), b"lloworld");
    }

    #[test]
    fn test_freeze_slice_clone_refcount() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0x42; 100]);
        let iobuf = buf.freeze();
        let slice = iobuf.slice(10..50);
        let clone1 = slice.clone();
        let clone2 = iobuf.clone();

        drop(iobuf);
        drop(slice);
        assert_eq!(get_allocated(&pool, page), 1); // Still held by clones

        drop(clone1);
        assert_eq!(get_allocated(&pool, page), 1); // Still held by clone2

        drop(clone2);
        assert_eq!(get_allocated(&pool, page), 0); // Finally returned
    }

    #[test]
    fn test_truncate_beyond_len_is_noop() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        // BytesMut behavior
        let mut bytes = BytesMut::with_capacity(100);
        bytes.resize(50, 0xAA);
        bytes.truncate(100); // Should be no-op
        assert_eq!(bytes.len(), 50);

        // PooledBufMut should match
        let mut pooled = pool.try_alloc(100).unwrap();
        pooled.put_slice(&[0xAA; 50]);
        pooled.truncate(100); // Should be no-op
        assert_eq!(pooled.len(), 50);
    }

    #[test]
    fn test_freeze_empty_after_clear() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0xAA; 50]);
        buf.clear();

        let frozen = buf.freeze();
        assert!(frozen.is_empty());
        assert_eq!(frozen.len(), 0);

        // Should still return to pool on drop
        drop(frozen);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_alignment_after_advance() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);

        let mut buf = pool.try_alloc(100).unwrap();
        buf.put_slice(&[0; 100]);

        // Initially aligned
        assert_eq!(buf.as_mut_ptr() as usize % page, 0);

        // After advance, alignment may be broken
        Buf::advance(&mut buf, 7);
        // Pointer is now at offset 7, not page-aligned
        assert_ne!(buf.as_mut_ptr() as usize % page, 0);
    }
}
