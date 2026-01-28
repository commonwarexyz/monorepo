//! Buffer pool for efficient I/O operations.
//!
//! Provides page-aligned, pooled buffers that can be reused to reduce allocation
//! overhead.

use super::{IoBuf, IoBufMut};
use bytes::{Buf, BufMut, Bytes};
use crossbeam_queue::ArrayQueue;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::Registry,
};
use std::{
    alloc::{alloc, dealloc, Layout},
    mem::ManuallyDrop,
    ptr::NonNull,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Weak,
    },
};

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
/// Uses 128 bytes for x86_64 and aarch64 (common for modern CPUs with
/// prefetching), and 64 bytes for other architectures.
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
    pub min_size: usize,
    /// Maximum buffer size. Must be a power of two and >= min_size.
    pub max_size: usize,
    /// Maximum number of buffers per size class.
    pub max_per_class: usize,
    /// Whether to pre-allocate all buffers on pool creation.
    pub prefill: bool,
    /// Buffer alignment. Must be a power of two.
    /// Use `page_size()` for storage I/O, `cache_line_size()` for network I/O.
    pub alignment: usize,
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self::for_network()
    }
}

impl BufferPoolConfig {
    /// Network I/O preset: cache-line aligned, cache_line_size to 1MB buffers,
    /// 4096 per class, not prefilled.
    ///
    /// Network operations typically need multiple concurrent buffers per connection
    /// (message, encoding, encryption) so we allow 4096 buffers per size class.
    /// Cache-line alignment is used because network buffers don't require page
    /// alignment for DMA, and smaller alignment reduces internal fragmentation.
    pub const fn for_network() -> Self {
        let cache_line = cache_line_size();
        Self {
            min_size: cache_line,
            max_size: 1048576,
            max_per_class: 4096,
            prefill: false,
            alignment: cache_line,
        }
    }

    /// Storage I/O preset: page-aligned, page_size to 64KB buffers, 32 per class,
    /// not prefilled.
    ///
    /// Page alignment is required for direct I/O and efficient DMA transfers.
    pub fn for_storage() -> Self {
        let page = page_size();
        Self {
            min_size: page,
            max_size: 64 * 1024,
            max_per_class: 32,
            prefill: false,
            alignment: page,
        }
    }

    /// Validates the configuration.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `alignment` is not a power of two
    /// - `min_size` is not a power of two
    /// - `max_size` is not a power of two
    /// - `min_size` < `alignment`
    /// - `max_size` < `min_size`
    /// - `max_per_class` is 0
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
        assert!(self.max_per_class > 0, "max_per_class must be > 0");
    }

    /// Returns the number of size classes.
    const fn num_classes(&self) -> usize {
        if self.max_size < self.min_size {
            return 0;
        }
        // Classes are: min_size, min_size*2, min_size*4, ..., max_size
        (self.max_size / self.min_size).trailing_zeros() as usize + 1
    }

    /// Returns the size class index for a given size.
    /// Returns None if size > max_size.
    const fn class_index(&self, size: usize) -> Option<usize> {
        if size > self.max_size {
            return None;
        }
        if size <= self.min_size {
            return Some(0);
        }
        // Find the smallest power-of-two class that fits
        let size_class = size.next_power_of_two();
        let index = (size_class / self.min_size).trailing_zeros() as usize;
        if index < self.num_classes() {
            Some(index)
        } else {
            None
        }
    }

    /// Returns the buffer size for a given class index.
    const fn class_size(&self, index: usize) -> usize {
        self.min_size << index
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
    fn new(registry: &mut Registry, config: &BufferPoolConfig) -> Self {
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

        // Initialize metrics for all size classes
        for i in 0..config.num_classes() {
            let label = SizeClassLabel {
                size_class: config.class_size(i) as u64,
            };
            let _ = metrics.allocated.get_or_create(&label);
            let _ = metrics.available.get_or_create(&label);
            let _ = metrics.allocations_total.get_or_create(&label);
            let _ = metrics.exhausted_total.get_or_create(&label);
        }

        metrics
    }
}

/// An aligned buffer.
///
/// The buffer is allocated with the specified alignment for efficient I/O operations.
/// Deallocates itself on drop using the stored alignment.
pub(crate) struct AlignedBuffer {
    ptr: NonNull<u8>,
    capacity: usize,
    alignment: usize,
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
    /// Panics if allocation fails or alignment is not a power of two.
    fn new(capacity: usize, alignment: usize) -> Self {
        let layout = Layout::from_size_align(capacity, alignment).expect("invalid layout");

        // SAFETY: Layout is valid (non-zero size, power-of-two alignment).
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr).expect("allocation failed");

        Self {
            ptr,
            capacity,
            alignment,
        }
    }

    /// Returns the capacity of the buffer.
    #[inline]
    const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns a raw pointer to the buffer.
    #[inline]
    const fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        let layout =
            Layout::from_size_align(self.capacity, self.alignment).expect("invalid layout");
        // SAFETY: ptr was allocated with this layout.
        unsafe { dealloc(self.ptr.as_ptr(), layout) };
    }
}

/// Per-size-class state.
struct SizeClass {
    /// The buffer size for this class.
    size: usize,
    /// Buffer alignment.
    alignment: usize,
    /// Free list of available buffers.
    freelist: ArrayQueue<AlignedBuffer>,
    /// Number of buffers currently allocated (out of pool).
    allocated: AtomicUsize,
    /// Total buffers ever created for this class (monotonically increasing).
    /// Used to enforce `max_per_class` limit without races.
    total_created: AtomicUsize,
    /// Total allocations from this class (includes reuse from freelist).
    total_allocations: AtomicU64,
}

impl SizeClass {
    fn new(size: usize, alignment: usize, max_buffers: usize) -> Self {
        Self {
            size,
            alignment,
            freelist: ArrayQueue::new(max_buffers),
            allocated: AtomicUsize::new(0),
            total_created: AtomicUsize::new(0),
            total_allocations: AtomicU64::new(0),
        }
    }

    /// Pre-fill the freelist with buffers.
    fn prefill(&self, max_buffers: usize) {
        for _ in 0..max_buffers {
            if self
                .freelist
                .push(AlignedBuffer::new(self.size, self.alignment))
                .is_err()
            {
                break;
            }
            self.total_created.fetch_add(1, Ordering::Relaxed);
        }
    }
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
    /// Retries a few times on CAS contention to avoid unnecessary fallback
    /// to heap allocations when pool capacity is available.
    fn try_alloc(&self, class_index: usize) -> Option<AlignedBuffer> {
        const MAX_RETRIES: usize = 3;

        let class = &self.classes[class_index];
        let label = SizeClassLabel {
            size_class: class.size as u64,
        };

        for _ in 0..MAX_RETRIES {
            // Try to get a buffer from the freelist
            if let Some(buffer) = class.freelist.pop() {
                class.allocated.fetch_add(1, Ordering::Relaxed);
                class.total_allocations.fetch_add(1, Ordering::Relaxed);

                self.metrics.allocations_total.get_or_create(&label).inc();
                self.metrics.allocated.get_or_create(&label).inc();
                self.metrics.available.get_or_create(&label).dec();

                return Some(buffer);
            }

            // Freelist empty - try to create a new buffer if under limit.
            // Use total_created (not allocated + freelist.len()) to avoid races.
            let created = class.total_created.load(Ordering::Acquire);
            if created >= self.config.max_per_class {
                // At hard limit, no point retrying
                break;
            }

            // Try to reserve a slot for a new buffer
            if class
                .total_created
                .compare_exchange(created, created + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                class.allocated.fetch_add(1, Ordering::Relaxed);
                class.total_allocations.fetch_add(1, Ordering::Relaxed);
                self.metrics.allocations_total.get_or_create(&label).inc();
                self.metrics.allocated.get_or_create(&label).inc();

                return Some(AlignedBuffer::new(class.size, class.alignment));
            }
            // CAS failed due to contention, hint CPU and retry
            std::hint::spin_loop();
        }

        // Pool exhausted
        self.metrics.exhausted_total.get_or_create(&label).inc();
        None
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
            match class.freelist.push(buffer) {
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

/// A pool of reusable, page-aligned buffers.
///
/// Buffers are organized into power-of-two size classes. When a buffer is requested,
/// the smallest size class that fits is used. Buffers are automatically returned to
/// the pool when dropped.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<BufferPoolInner>,
}

impl BufferPool {
    /// Creates a new buffer pool with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if the configuration is invalid.
    pub fn new(config: BufferPoolConfig, registry: &mut Registry) -> Self {
        config.validate();

        let metrics = PoolMetrics::new(registry, &config);

        let mut classes = Vec::with_capacity(config.num_classes());
        for i in 0..config.num_classes() {
            let size = config.class_size(i);
            let class = SizeClass::new(size, config.alignment, config.max_per_class);
            if config.prefill {
                class.prefill(config.max_per_class);
            }
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

    /// Allocates a buffer with the given capacity.
    ///
    /// Returns `None` if:
    /// - `capacity` exceeds the maximum buffer size
    /// - The pool is exhausted for the required size class
    ///
    /// The returned buffer has `len() == 0` and `capacity() >= capacity`,
    /// matching the semantics of [`IoBufMut::with_capacity`] and
    /// [`BytesMut::with_capacity`]. Use [`IoBufMut::resize`] to initialize
    /// the buffer to a specific length.
    ///
    /// The actual capacity is rounded up to the next power-of-two size class.
    /// The buffer will be returned to the pool when dropped.
    pub fn alloc(&self, capacity: usize) -> Option<IoBufMut> {
        let class_index = match self.inner.config.class_index(capacity) {
            Some(idx) => idx,
            None => {
                self.inner.metrics.oversized_total.inc();
                return None;
            }
        };

        let buffer = self.inner.try_alloc(class_index)?;
        let pooled = PooledBufMut::new(buffer, Arc::downgrade(&self.inner));
        Some(IoBufMut::from_pooled(pooled))
    }

    /// Allocates a buffer optimized for I/O operations.
    ///
    /// Currently identical to [`Self::alloc`]. In the future, this may return
    /// buffers registered with io_uring for zero-copy I/O.
    pub fn alloc_for_io(&self, capacity: usize) -> Option<IoBufMut> {
        self.alloc(capacity)
    }

    /// Returns the pool configuration.
    pub fn config(&self) -> &BufferPoolConfig {
        &self.inner.config
    }
}

/// Composite type holding buffer pools for different I/O domains.
#[derive(Clone)]
pub struct BufferPools {
    network: BufferPool,
    storage: BufferPool,
}

impl BufferPools {
    /// Creates buffer pools with the given configurations.
    pub fn new(
        network_config: BufferPoolConfig,
        storage_config: BufferPoolConfig,
        registry: &mut Registry,
    ) -> Self {
        let network = BufferPool::new(network_config, registry.sub_registry_with_prefix("network"));
        let storage = BufferPool::new(storage_config, registry.sub_registry_with_prefix("storage"));
        Self { network, storage }
    }

    /// Creates buffer pools with default configurations.
    pub fn with_defaults(registry: &mut Registry) -> Self {
        Self::new(
            BufferPoolConfig::for_network(),
            BufferPoolConfig::for_storage(),
            registry,
        )
    }

    /// Returns the network buffer pool.
    pub const fn network(&self) -> &BufferPool {
        &self.network
    }

    /// Returns the storage buffer pool.
    pub const fn storage(&self) -> &BufferPool {
        &self.storage
    }
}

/// A mutable buffer from the pool.
///
/// When dropped, the underlying buffer is returned to the pool (if it came from one).
/// Buffers that were allocated as fallback (when the pool was exhausted) are simply
/// deallocated on drop.
pub struct PooledBufMut {
    buffer: ManuallyDrop<AlignedBuffer>,
    /// Read cursor position (for `Buf` trait).
    cursor: usize,
    /// Number of bytes written (initialized).
    len: usize,
    /// Reference to the pool. `Weak::new()` for fallback allocations.
    pool: Weak<BufferPoolInner>,
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
            buffer: ManuallyDrop::new(buffer),
            cursor: 0,
            len: 0,
            pool,
        }
    }

    /// Returns the number of readable bytes remaining in the buffer.
    ///
    /// This is `written_len - cursor`, matching `BytesMut` semantics.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len - self.cursor
    }

    /// Returns true if no readable bytes remain.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.cursor == self.len
    }

    /// Returns the total capacity of the buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    /// Returns a raw mutable pointer to the buffer data.
    ///
    /// This points to the current read position (cursor), matching `BytesMut` semantics.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        // SAFETY: cursor is always <= capacity
        unsafe { self.buffer.as_ptr().add(self.cursor) }
    }

    /// Sets the length of the initialized data.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `len` bytes starting from the buffer's pointer
    /// have been initialized.
    #[inline]
    pub unsafe fn set_len(&mut self, len: usize) {
        debug_assert!(len <= self.capacity());
        self.len = len;
    }

    /// Clears the buffer, resetting both cursor and length to 0.
    #[inline]
    pub const fn clear(&mut self) {
        self.cursor = 0;
        self.len = 0;
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

    /// Resizes the buffer to `new_len`, filling new bytes with `value`.
    ///
    /// If `new_len` is less than the current length, the buffer is truncated.
    /// If `new_len` is greater and exceeds capacity, this will:
    /// 1. Try to get a larger buffer from the pool
    /// 2. Fall back to direct allocation if the pool is exhausted
    ///
    /// When a larger buffer is obtained, data from `cursor..len` is copied
    /// to the new buffer, and the cursor is reset to 0.
    pub fn resize(&mut self, new_len: usize, value: u8) {
        let current_len = self.len();

        if new_len <= current_len {
            // Truncating - just adjust length (cursor stays the same)
            self.len = self.cursor + new_len;
            return;
        }

        // Growing - check if we need a bigger buffer
        let required_capacity = self.cursor + new_len;
        if required_capacity > self.capacity() {
            // Need a bigger buffer
            let new_capacity = required_capacity.next_power_of_two().max(page_size());

            // Try to get from pool first, fall back to direct allocation
            let (new_buffer, new_pool) = self
                .pool
                .upgrade()
                .and_then(|pool| {
                    let idx = pool.config.class_index(new_capacity)?;
                    let buf = pool.try_alloc(idx)?;
                    Some((buf, Arc::downgrade(&pool)))
                })
                .unwrap_or_else(|| {
                    // Use same alignment as current buffer for fallback
                    let alignment = self.buffer.alignment;
                    (AlignedBuffer::new(new_capacity, alignment), Weak::new())
                });

            // Copy existing data (only the readable portion: cursor..len)
            if current_len > 0 {
                // SAFETY: Both pointers are valid, non-overlapping, and current_len bytes are initialized.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        self.buffer.as_ptr().add(self.cursor),
                        new_buffer.as_ptr(),
                        current_len,
                    );
                }
            }

            // Return old buffer to pool, or drop it (Drop handles deallocation)
            // SAFETY: We're replacing the buffer, and no other code will access the old one.
            let old_buffer = unsafe { ManuallyDrop::take(&mut self.buffer) };
            if let Some(pool) = self.pool.upgrade() {
                pool.return_buffer(old_buffer);
            }
            // else: old_buffer is dropped here, which deallocates it

            // Install new buffer with cursor reset to 0
            self.buffer = ManuallyDrop::new(new_buffer);
            self.cursor = 0;
            self.len = current_len;
            self.pool = new_pool;
        }

        // Fill new bytes with value
        let fill_start = self.len;
        let fill_end = self.cursor + new_len;
        // SAFETY: We verified capacity above, and fill_start..fill_end is within bounds.
        unsafe {
            std::ptr::write_bytes(
                self.buffer.as_ptr().add(fill_start),
                value,
                fill_end - fill_start,
            );
        }
        self.len = fill_end;
    }

    /// Freezes the buffer into an immutable `IoBuf`.
    ///
    /// Only the readable portion (`cursor..len`) is included in the result.
    /// The underlying buffer will be returned to the pool when all references
    /// to the `IoBuf` (including slices) are dropped.
    pub fn freeze(mut self) -> IoBuf {
        // SAFETY: We're consuming self and use mem::forget to prevent Drop from running.
        let buffer = unsafe { ManuallyDrop::take(&mut self.buffer) };
        let cursor = self.cursor;
        let len = self.len;
        // Move the weak out instead of cloning, otherwise cloning and then forgetting
        // would leak the original weak reference.
        let pool = std::mem::take(&mut self.pool);

        // Prevent Drop from running
        std::mem::forget(self);

        Bytes::from_owner(PooledOwner::new(buffer, cursor, len, pool)).into()
    }
}

impl AsRef<[u8]> for PooledBufMut {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: bytes from cursor..len have been initialized.
        unsafe { std::slice::from_raw_parts(self.buffer.as_ptr().add(self.cursor), self.len()) }
    }
}

impl AsMut<[u8]> for PooledBufMut {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        let len = self.len();
        // SAFETY: bytes from cursor..len have been initialized.
        unsafe { std::slice::from_raw_parts_mut(self.buffer.as_ptr().add(self.cursor), len) }
    }
}

impl Drop for PooledBufMut {
    fn drop(&mut self) {
        // SAFETY: Drop is only called once, and freeze() uses mem::forget to skip this.
        let buffer = unsafe { ManuallyDrop::take(&mut self.buffer) };
        if let Some(pool) = self.pool.upgrade() {
            pool.return_buffer(buffer);
        }
        // else: buffer is dropped here, which deallocates it
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
                self.buffer.as_ptr().add(self.cursor),
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
unsafe impl BufMut for PooledBufMut {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.capacity() - self.len
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
        let cap = self.capacity();
        let len = self.len;
        // SAFETY: We have exclusive access and the slice is within capacity.
        unsafe {
            let ptr = self.buffer.as_ptr().add(len);
            bytes::buf::UninitSlice::from_raw_parts_mut(ptr, cap - len)
        }
    }
}

/// Owner for pooled bytes that returns the buffer to the pool on drop.
struct PooledOwner {
    buffer: ManuallyDrop<AlignedBuffer>,
    /// Start offset of the data.
    cursor: usize,
    /// End offset of the data (exclusive).
    len: usize,
    pool: Weak<BufferPoolInner>,
}

impl PooledOwner {
    const fn new(
        buffer: AlignedBuffer,
        cursor: usize,
        len: usize,
        pool: Weak<BufferPoolInner>,
    ) -> Self {
        Self {
            buffer: ManuallyDrop::new(buffer),
            cursor,
            len,
            pool,
        }
    }
}

// Required for Bytes::from_owner
impl AsRef<[u8]> for PooledOwner {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: bytes from cursor..len have been initialized.
        unsafe {
            std::slice::from_raw_parts(
                self.buffer.as_ptr().add(self.cursor),
                self.len - self.cursor,
            )
        }
    }
}

impl Drop for PooledOwner {
    fn drop(&mut self) {
        // SAFETY: Drop is only called once.
        let buffer = unsafe { ManuallyDrop::take(&mut self.buffer) };
        if let Some(pool) = self.pool.upgrade() {
            pool.return_buffer(buffer);
        }
        // else: buffer is dropped here, which deallocates it
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> Registry {
        Registry::default()
    }

    /// Creates a test config with page alignment.
    fn test_config(min_size: usize, max_size: usize, max_per_class: usize) -> BufferPoolConfig {
        BufferPoolConfig {
            min_size,
            max_size,
            max_per_class,
            prefill: false,
            alignment: page_size(),
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
    fn test_config_validation() {
        let page = page_size();
        let config = test_config(page, page * 4, 10);
        config.validate();
    }

    #[test]
    #[should_panic(expected = "min_size must be a power of two")]
    fn test_config_invalid_min_size() {
        let config = BufferPoolConfig {
            min_size: 3000,
            max_size: 8192,
            max_per_class: 10,
            prefill: false,
            alignment: page_size(),
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
        let buf = pool.alloc(100).expect("alloc should succeed");
        assert!(buf.capacity() >= page);
        assert_eq!(buf.len(), 0);

        // Drop returns to pool
        drop(buf);

        // Can allocate again
        let buf2 = pool.alloc(100).expect("alloc should succeed");
        assert!(buf2.capacity() >= page);
        assert_eq!(buf2.len(), 0);
    }

    #[test]
    fn test_pool_exhaustion() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        // Allocate max buffers
        let _buf1 = pool.alloc(100).expect("first alloc should succeed");
        let _buf2 = pool.alloc(100).expect("second alloc should succeed");

        // Third allocation should fail
        assert!(pool.alloc(100).is_none());
    }

    #[test]
    fn test_pool_oversized() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 2, 10), &mut registry);

        // Request larger than max_size
        assert!(pool.alloc(page * 4).is_none());
    }

    #[test]
    fn test_pool_size_classes() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 10), &mut registry);

        // Small request gets smallest class
        let buf1 = pool.alloc(100).unwrap();
        assert_eq!(buf1.capacity(), page);

        // Larger request gets appropriate class
        let buf2 = pool.alloc(page + 1).unwrap();
        assert_eq!(buf2.capacity(), page * 2);

        let buf3 = pool.alloc(page * 3).unwrap();
        assert_eq!(buf3.capacity(), page * 4);
    }

    #[test]
    fn test_pooled_buf_mut_freeze() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        // Allocate and initialize a buffer
        let mut buf = pool.alloc(11).unwrap();
        buf.resize(11, 0);
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
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(
            BufferPoolConfig {
                min_size: page,
                max_size: page,
                max_per_class: 5,
                prefill: true,
                alignment: page,
            },
            &mut registry,
        );

        // Should be able to allocate max_per_class buffers immediately
        let mut bufs = Vec::new();
        for _ in 0..5 {
            bufs.push(pool.alloc(100).expect("alloc should succeed"));
        }

        // Next allocation should fail
        assert!(pool.alloc(100).is_none());
    }

    /// Test Buf trait implementation on pooled buffers.
    #[test]
    fn test_pooled_buf_trait() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 10), &mut registry);

        // Allocate and initialize a buffer
        let mut pooled = pool.alloc(100).unwrap();
        pooled.resize(100, 0);
        assert_eq!(pooled.len(), 100);
        assert_eq!(Buf::remaining(&pooled), 100);

        // Advance (read cursor)
        Buf::advance(&mut pooled, 40);
        assert_eq!(pooled.len(), 60);
        assert_eq!(Buf::remaining(&pooled), 60);

        // Advance to end
        Buf::advance(&mut pooled, 60);
        assert_eq!(pooled.len(), 0);
        assert!(pooled.is_empty());

        // Freeze empty buffer
        let frozen = pooled.freeze();
        assert!(frozen.is_empty());
    }

    /// Test that freeze preserves only remaining data (after advance).
    #[test]
    fn test_pooled_freeze_after_advance() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        // Allocate and fill with known pattern
        let mut pooled = pool.alloc(11).unwrap();
        pooled.resize(11, 0x42);
        assert_eq!(pooled.len(), 11);

        // Advance past first 6 bytes
        Buf::advance(&mut pooled, 6);
        assert_eq!(pooled.len(), 5);

        // Freeze - should only contain remaining 5 bytes
        let frozen = pooled.freeze();
        assert_eq!(frozen.len(), 5);
        assert!(frozen.as_ref().iter().all(|&b| b == 0x42));
    }

    /// Test clear resets both cursor and length.
    #[test]
    fn test_pooled_clear() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        let mut pooled = pool.alloc(100).unwrap();
        pooled.resize(100, 0);
        assert_eq!(pooled.len(), 100);

        // Advance cursor
        Buf::advance(&mut pooled, 50);
        assert_eq!(pooled.len(), 50); // remaining readable bytes

        // Clear should reset everything
        pooled.clear();
        assert_eq!(pooled.len(), 0);
        assert!(pooled.is_empty());
    }

    #[test]
    fn test_config_default() {
        let config = BufferPoolConfig::default();
        config.validate();
        assert_eq!(config.min_size, cache_line_size());
        assert_eq!(config.max_size, 1048576);
        assert_eq!(config.max_per_class, 4096);
        assert!(!config.prefill);
        assert_eq!(config.alignment, cache_line_size());
    }

    #[test]
    fn test_config_for_network() {
        let config = BufferPoolConfig::for_network();
        config.validate();
        assert_eq!(config.min_size, cache_line_size());
        assert_eq!(config.max_size, 1048576);
        assert_eq!(config.max_per_class, 4096);
        assert!(!config.prefill);
        assert_eq!(config.alignment, cache_line_size());
    }

    #[test]
    fn test_config_for_storage() {
        let config = BufferPoolConfig::for_storage();
        config.validate();
        assert_eq!(config.min_size, page_size());
        assert_eq!(config.max_size, 64 * 1024);
        assert_eq!(config.max_per_class, 32);
        assert!(!config.prefill);
        assert_eq!(config.alignment, page_size());
    }

    #[test]
    fn test_buffer_pools_with_defaults() {
        let mut registry = test_registry();
        let pools = BufferPools::with_defaults(&mut registry);

        // Verify network pool works (cache-line aligned)
        let net_buf = pools.network().alloc(1024).expect("network alloc failed");
        assert!(net_buf.capacity() >= cache_line_size());

        // Verify storage pool works (page-aligned)
        let storage_buf = pools.storage().alloc(1024).expect("storage alloc failed");
        assert!(storage_buf.capacity() >= page_size());
    }

    #[test]
    fn test_buffer_pools_new() {
        let mut registry = test_registry();
        let pools = BufferPools::new(
            BufferPoolConfig::for_network(),
            BufferPoolConfig::for_storage(),
            &mut registry,
        );

        // Access and use both pools
        let net_cfg = pools.network().config();
        assert_eq!(net_cfg.max_per_class, 4096);

        let storage_cfg = pools.storage().config();
        assert_eq!(storage_cfg.max_per_class, 32);
    }

    #[test]
    fn test_pooled_resize_grow_within_capacity() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        // Allocate and initialize a small buffer
        let mut buf = pool.alloc(50).unwrap();
        buf.resize(50, 0x11); // Fill with known pattern
        assert_eq!(buf.len(), 50);

        // Grow within capacity (page size is at least 4096)
        buf.resize(100, 0xAB);
        assert_eq!(buf.len(), 100);
        // First 50 bytes should still have original pattern
        assert!(buf.as_ref()[..50].iter().all(|&b| b == 0x11));
        // New bytes should be filled with 0xAB
        assert!(buf.as_ref()[50..].iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_pooled_resize_truncate() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 10), &mut registry);

        // Allocate and initialize a buffer
        let mut buf = pool.alloc(100).unwrap();
        buf.resize(100, 0);
        assert_eq!(buf.len(), 100);

        // Truncate
        buf.resize(30, 0);
        assert_eq!(buf.len(), 30);
    }

    #[test]
    fn test_pooled_resize_grow_beyond_capacity() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page * 4, 10), &mut registry);

        // Allocate and initialize a buffer at minimum size class
        let mut buf = pool.alloc(100).unwrap();
        buf.resize(100, 0x22); // Fill with known pattern
        let original_capacity = buf.capacity();
        assert_eq!(buf.len(), 100);

        // Grow beyond capacity - should get a new buffer from the pool
        let new_size = original_capacity + 100;
        buf.resize(new_size, 0xAB);
        assert!(buf.capacity() >= new_size);
        assert_eq!(buf.len(), new_size);
        // Original data should be preserved
        assert!(buf.as_ref()[..100].iter().all(|&b| b == 0x22));
        // New bytes should be filled with 0xAB
        assert!(buf.as_ref()[100..].iter().all(|&b| b == 0xAB));
    }

    /// Helper to get the number of allocated buffers for a size class.
    fn get_allocated(pool: &BufferPool, size: usize) -> usize {
        let class_index = pool.inner.config.class_index(size).unwrap();
        pool.inner.classes[class_index]
            .allocated
            .load(Ordering::Relaxed)
    }

    /// Helper to get the number of available buffers in freelist for a size class.
    fn get_available(pool: &BufferPool, size: usize) -> usize {
        let class_index = pool.inner.config.class_index(size).unwrap();
        pool.inner.classes[class_index].freelist.len()
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
        let buf = pool.alloc(100).unwrap();
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

        let buf = pool.alloc(100).unwrap();
        let iobuf = buf.freeze();

        // Clone the IoBuf multiple times (this clones the inner Bytes via Arc)
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

        let mut buf = pool.alloc(100).unwrap();
        buf.resize(100, 0);
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
    fn test_copy_to_bytes_on_pooled_buffer() {
        use crate::Buf;

        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.alloc(100).unwrap();
        buf.resize(100, 0x42);
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
    fn test_high_volume_alloc_freeze_cycle() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 4), &mut registry);

        // Rapidly allocate and free many buffers
        for i in 0..1000 {
            let buf = pool
                .alloc(100)
                .unwrap_or_else(|| panic!("alloc {} should succeed", i));
            let iobuf = buf.freeze();
            drop(iobuf);
        }

        // All buffers should be returned
        assert_eq!(get_allocated(&pool, page), 0);
        // Freelist should have buffers (up to max_per_class)
        assert!(get_available(&pool, page) <= 4);
    }

    #[test]
    fn test_concurrent_clones_and_drops() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 4), &mut registry);

        // Simulate the pattern in Messenger::content where we clone for multiple recipients
        for _ in 0..100 {
            let buf = pool.alloc(100).unwrap();
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
    fn test_encode_pattern_like_messenger() {
        // This simulates what Messenger::content does:
        // 1. Receive message as IoBufMut
        // 2. Freeze it into Data.message
        // 3. Allocate encoding buffer from pool
        // 4. Write/copy data into encoding buffer
        // 5. Freeze encoding buffer
        // 6. Clone for multiple recipients

        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 8), &mut registry);

        for _ in 0..100 {
            // Step 1: Incoming message
            let mut incoming = pool.alloc(100).unwrap();
            incoming.resize(100, 0x42);

            // Step 2: Freeze into "Data.message"
            let data_message = incoming.freeze();

            // Step 3: Allocate encoding buffer
            let mut encoding_buf = pool.alloc(200).unwrap();
            encoding_buf.resize(200, 0);

            // Step 4: Copy data into encoding buffer (simulating encode)
            encoding_buf.as_mut()[..100].copy_from_slice(data_message.as_ref());

            // Data.message is no longer needed after encoding
            drop(data_message);

            // Step 5: Freeze encoding buffer into "EncodedData.payload"
            let encoded_payload = encoding_buf.freeze();

            // Step 6: Clone for multiple recipients
            let recipient_copies: Vec<_> = (0..5).map(|_| encoded_payload.clone()).collect();
            drop(encoded_payload);

            // Simulate recipients processing and dropping
            for copy in recipient_copies {
                drop(copy);
            }
        }

        // All buffers should be returned
        assert_eq!(get_allocated(&pool, page), 0);
    }

    #[test]
    fn test_iobuf_to_iobufmut_conversion_returns_pooled_buffer() {
        // This tests the IoBuf -> IoBufMut conversion that happens
        // when send() takes impl Into<IoBufMut>
        use crate::IoBufMut;

        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let buf = pool.alloc(100).unwrap();
        assert_eq!(get_allocated(&pool, page), 1);

        let iobuf = buf.freeze();
        assert_eq!(get_allocated(&pool, page), 1);

        // This is what happens when you call send(iobuf) where send takes impl Into<IoBufMut>
        // The IoBuf is converted to IoBufMut via From<IoBuf> for IoBufMut
        let iobufmut: IoBufMut = iobuf.into();

        // The conversion copies data to a new BytesMut and drops the original Bytes
        // So the pooled buffer should be returned!
        assert_eq!(
            get_allocated(&pool, page),
            0,
            "pooled buffer should be returned after IoBuf->IoBufMut conversion"
        );
        assert_eq!(get_available(&pool, page), 1);

        // The IoBufMut is now backed by BytesMut, not the pool
        drop(iobufmut);
        // Pool state unchanged
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_stream_send_pattern() {
        // Simulates what stream::Sender::send does:
        // 1. Takes impl Into<IoBufs>
        // 2. Allocates encryption buffer from pool
        // 3. Copies plaintext into encryption buffer
        // 4. Encrypts in place
        // 5. Freezes and sends

        use crate::{Buf, IoBufs};

        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 4), &mut registry);

        for _ in 0..100 {
            // Incoming data (could be IoBuf or IoBufMut)
            let mut incoming = pool.alloc(100).unwrap();
            incoming.resize(100, 0x42);
            let incoming_iobuf = incoming.freeze();

            // Convert to IoBufs (what send() does)
            let mut bufs: IoBufs = incoming_iobuf.into();
            let plaintext_len = bufs.remaining();

            // Allocate encryption buffer with capacity (no init needed, we write to it)
            let ciphertext_len = plaintext_len + 16; // +16 for tag
            let mut encryption_buf = pool.alloc(ciphertext_len).unwrap();
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
    fn test_bytes_from_owner_behavior() {
        // Test that Bytes::from_owner correctly handles our PooledOwner

        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let buf = pool.alloc(100).unwrap();
        let iobuf = buf.freeze();

        // Get the inner Bytes
        let bytes: Bytes = iobuf.into();
        assert_eq!(get_allocated(&pool, page), 1);

        // Clone the Bytes
        let bytes2 = bytes.clone();
        assert_eq!(get_allocated(&pool, page), 1);

        // Drop one
        drop(bytes);
        assert_eq!(get_allocated(&pool, page), 1);

        // Drop the other - now buffer should return
        drop(bytes2);
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 1);
    }

    #[test]
    fn test_multithreaded_alloc_freeze_return() {
        use std::{sync::Arc, thread};

        let page = page_size();
        let mut registry = test_registry();
        let pool = Arc::new(BufferPool::new(test_config(page, page, 100), &mut registry));

        let mut handles = vec![];

        // Spawn multiple threads that allocate, freeze, clone, and drop
        for _ in 0..10 {
            let pool = pool.clone();
            let handle = thread::spawn(move || {
                for _ in 0..1000 {
                    if let Some(buf) = pool.alloc(100) {
                        let iobuf = buf.freeze();

                        // Clone a few times
                        let clones: Vec<_> = (0..5).map(|_| iobuf.clone()).collect();
                        drop(iobuf);

                        // Drop clones
                        for clone in clones {
                            drop(clone);
                        }
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
        use std::{sync::mpsc, thread};

        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 100), &mut registry);

        let (tx, rx) = mpsc::channel();

        // Allocate and freeze on main thread
        for _ in 0..50 {
            let buf = pool.alloc(100).unwrap();
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
        println!("Cross-thread: available = {}", get_available(&pool, page));
    }

    #[test]
    fn test_pool_dropped_before_buffer() {
        // What happens if the pool is dropped while buffers are still in use?
        // The Weak reference should fail to upgrade, and the buffer should just be deallocated.

        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(test_config(page, page, 2), &mut registry);

        let mut buf = pool.alloc(100).unwrap();
        buf.resize(100, 0);
        let iobuf = buf.freeze();

        // Drop the pool while buffer is still alive
        drop(pool);

        // Buffer should still be usable
        assert_eq!(iobuf.len(), 100);

        // Dropping the buffer should not panic (Weak upgrade fails, buffer is deallocated)
        drop(iobuf);
        // No assertion here - we just want to make sure it doesn't panic
    }
}
