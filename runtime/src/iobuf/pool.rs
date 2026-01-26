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
    // SAFETY: sysconf is safe to call and _SC_PAGESIZE always succeeds on Unix systems.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(not(unix))]
#[allow(clippy::missing_const_for_fn)]
fn page_size() -> usize {
    4096
}

/// Configuration for a buffer pool.
#[derive(Debug, Clone)]
pub struct BufferPoolConfig {
    /// Minimum buffer size. Must be >= page_size and a power of two.
    pub min_size: usize,
    /// Maximum buffer size. Must be a power of two and >= min_size.
    pub max_size: usize,
    /// Maximum number of buffers per size class.
    pub max_per_class: usize,
    /// Whether to pre-allocate all buffers on pool creation.
    pub prefill: bool,
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self::for_network()
    }
}

impl BufferPoolConfig {
    /// Network I/O preset: 4KB-64KB buffers, 64 per class, prefilled.
    pub fn for_network() -> Self {
        let page = page_size();
        Self {
            min_size: page,
            max_size: 64 * 1024,
            max_per_class: 64,
            prefill: true,
        }
    }

    /// Storage I/O preset: 4KB-64KB buffers, 32 per class, prefilled.
    pub fn for_storage() -> Self {
        let page = page_size();
        Self {
            min_size: page,
            max_size: 64 * 1024,
            max_per_class: 32,
            prefill: true,
        }
    }

    /// Validates the configuration.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `min_size` is not a power of two
    /// - `max_size` is not a power of two
    /// - `min_size` < page_size
    /// - `max_size` < `min_size`
    /// - `max_per_class` is 0
    fn validate(&self) {
        let page = page_size();
        assert!(
            self.min_size.is_power_of_two(),
            "min_size must be a power of two"
        );
        assert!(
            self.max_size.is_power_of_two(),
            "max_size must be a power of two"
        );
        assert!(
            self.min_size >= page,
            "min_size ({}) must be >= page_size ({})",
            self.min_size,
            page
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

/// A page-aligned buffer.
///
/// The buffer is allocated with page alignment for efficient I/O operations.
pub(crate) struct AlignedBuffer {
    ptr: NonNull<u8>,
    capacity: usize,
}

// SAFETY: AlignedBuffer owns its memory and can be sent between threads.
unsafe impl Send for AlignedBuffer {}
// SAFETY: AlignedBuffer's memory is not shared (no interior mutability of pointer).
unsafe impl Sync for AlignedBuffer {}

impl AlignedBuffer {
    /// Allocates a new page-aligned buffer with the given capacity.
    ///
    /// # Panics
    ///
    /// Panics if allocation fails.
    fn new(capacity: usize) -> Self {
        let page = page_size();
        let layout = Layout::from_size_align(capacity, page).expect("invalid layout");

        // SAFETY: Layout is valid (non-zero size, power-of-two alignment).
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr).expect("allocation failed");

        Self { ptr, capacity }
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
        let page = page_size();
        let layout = Layout::from_size_align(self.capacity, page).expect("invalid layout");
        // SAFETY: ptr was allocated with this layout in `new`.
        unsafe { dealloc(self.ptr.as_ptr(), layout) };
    }
}

/// Per-size-class state.
struct SizeClass {
    /// The buffer size for this class.
    size: usize,
    /// Free list of available buffers.
    freelist: ArrayQueue<AlignedBuffer>,
    /// Number of buffers currently allocated (out of pool).
    allocated: AtomicUsize,
    /// Total allocations from this class.
    total_allocations: AtomicU64,
}

impl SizeClass {
    fn new(size: usize, max_buffers: usize) -> Self {
        Self {
            size,
            freelist: ArrayQueue::new(max_buffers),
            allocated: AtomicUsize::new(0),
            total_allocations: AtomicU64::new(0),
        }
    }

    /// Pre-fill the freelist with buffers.
    fn prefill(&self) {
        while self.freelist.push(AlignedBuffer::new(self.size)).is_ok() {}
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
    fn try_alloc(&self, class_index: usize) -> Option<AlignedBuffer> {
        let class = &self.classes[class_index];
        let label = SizeClassLabel {
            size_class: class.size as u64,
        };

        // Try to get a buffer from the freelist
        if let Some(buffer) = class.freelist.pop() {
            class.allocated.fetch_add(1, Ordering::Relaxed);
            class.total_allocations.fetch_add(1, Ordering::Relaxed);

            self.metrics.allocations_total.get_or_create(&label).inc();
            self.metrics.allocated.get_or_create(&label).inc();
            self.metrics.available.get_or_create(&label).dec();

            return Some(buffer);
        }

        // Freelist empty - try to allocate a new buffer if under limit
        let current = class.allocated.load(Ordering::Relaxed);
        let available = class.freelist.len();
        let total = current + available;

        if total < self.config.max_per_class {
            // Try to increment allocated count
            if class
                .allocated
                .compare_exchange(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                class.total_allocations.fetch_add(1, Ordering::Relaxed);
                self.metrics.allocations_total.get_or_create(&label).inc();
                self.metrics.allocated.get_or_create(&label).inc();

                return Some(AlignedBuffer::new(class.size));
            }
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

            // Try to return to freelist, drop if full
            if class.freelist.push(buffer).is_ok() {
                self.metrics.available.get_or_create(&label).inc();
            }
        }
        // Buffer doesn't match any class - just drop it
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
            let class = SizeClass::new(size, config.max_per_class);
            if config.prefill {
                class.prefill();
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

    /// Allocates a buffer that can hold at least `size` bytes.
    ///
    /// Returns `None` if:
    /// - `size` exceeds the maximum buffer size
    /// - The pool is exhausted for the required size class
    ///
    /// The returned buffer is page-aligned and will be returned to the pool when dropped.
    pub fn alloc(&self, size: usize) -> Option<IoBufMut> {
        let class_index = match self.inner.config.class_index(size) {
            Some(idx) => idx,
            None => {
                self.inner.metrics.oversized_total.inc();
                return None;
            }
        };

        let buffer = self.inner.try_alloc(class_index)?;
        Some(IoBufMut::from_pooled(PooledBufMut::new(
            buffer,
            Arc::downgrade(&self.inner),
        )))
    }

    /// Allocates a buffer optimized for I/O operations.
    ///
    /// Currently identical to `alloc()`. In the future, this may return buffers
    /// that are registered with io_uring for zero-copy I/O.
    pub fn alloc_for_io(&self, size: usize) -> Option<IoBufMut> {
        self.alloc(size)
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

    /// Reserves capacity for at least `additional` more bytes.
    ///
    /// If the current buffer doesn't have enough space, this will:
    /// 1. Try to get a larger buffer from the pool
    /// 2. Fall back to direct allocation if the pool is exhausted
    ///
    /// Data from `cursor..len` is copied to the new buffer, and the cursor is reset to 0.
    pub fn reserve(&mut self, additional: usize) {
        let required = self.len() + additional;
        if required <= self.capacity() - self.cursor {
            return; // Already have enough space
        }

        // Need a bigger buffer
        let new_capacity = required.next_power_of_two().max(page_size());

        // Try to get from pool first, fall back to direct allocation
        let (new_buffer, new_pool) = self
            .pool
            .upgrade()
            .and_then(|pool| {
                let idx = pool.config.class_index(new_capacity)?;
                let buf = pool.try_alloc(idx)?;
                Some((buf, Arc::downgrade(&pool)))
            })
            .unwrap_or_else(|| (AlignedBuffer::new(new_capacity), Weak::new()));

        // Copy existing data (only the readable portion: cursor..len)
        let data_len = self.len();
        if data_len > 0 {
            // SAFETY: Both pointers are valid, non-overlapping, and data_len bytes are initialized.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.buffer.as_ptr().add(self.cursor),
                    new_buffer.as_ptr(),
                    data_len,
                );
            }
        }

        // Return old buffer to pool (if it came from one)
        // SAFETY: We're replacing the buffer, and no other code will access the old one.
        let old_buffer = unsafe { ManuallyDrop::take(&mut self.buffer) };
        if let Some(pool) = self.pool.upgrade() {
            pool.return_buffer(old_buffer);
        }
        // If no pool, old_buffer is dropped here

        // Install new buffer
        self.buffer = ManuallyDrop::new(new_buffer);
        self.cursor = 0;
        self.len = data_len;
        self.pool = new_pool;
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
        let pool = self.pool.clone();

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
        // If pool is gone, buffer is simply dropped (deallocated)
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
        // If pool is gone, buffer is simply dropped (deallocated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> Registry {
        Registry::default()
    }

    #[test]
    fn test_page_size() {
        let size = page_size();
        assert!(size >= 4096);
        assert!(size.is_power_of_two());
    }

    #[test]
    fn test_aligned_buffer() {
        let buf = AlignedBuffer::new(4096);
        assert_eq!(buf.capacity(), 4096);
        assert!((buf.as_ptr() as usize).is_multiple_of(page_size()));
    }

    #[test]
    fn test_config_validation() {
        let page = page_size();

        // Valid config
        let config = BufferPoolConfig {
            min_size: page,
            max_size: page * 4,
            max_per_class: 10,
            prefill: false,
        };
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
        };
        config.validate();
    }

    #[test]
    fn test_config_class_index() {
        let page = page_size();
        let config = BufferPoolConfig {
            min_size: page,
            max_size: page * 8,
            max_per_class: 10,
            prefill: false,
        };

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
        let pool = BufferPool::new(
            BufferPoolConfig {
                min_size: page,
                max_size: page * 4,
                max_per_class: 2,
                prefill: false,
            },
            &mut registry,
        );

        // Allocate a buffer
        let mut buf = pool.alloc(100).expect("alloc should succeed");
        assert!(buf.capacity() >= page);

        // Write some data
        buf.put_slice(b"hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_ref(), b"hello");

        // Drop returns to pool
        drop(buf);

        // Can allocate again
        let buf2 = pool.alloc(100).expect("alloc should succeed");
        assert!(buf2.capacity() >= page);
    }

    #[test]
    fn test_pool_exhaustion() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(
            BufferPoolConfig {
                min_size: page,
                max_size: page,
                max_per_class: 2,
                prefill: false,
            },
            &mut registry,
        );

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
        let pool = BufferPool::new(
            BufferPoolConfig {
                min_size: page,
                max_size: page * 2,
                max_per_class: 10,
                prefill: false,
            },
            &mut registry,
        );

        // Request larger than max_size
        assert!(pool.alloc(page * 4).is_none());
    }

    #[test]
    fn test_pool_size_classes() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(
            BufferPoolConfig {
                min_size: page,
                max_size: page * 4,
                max_per_class: 10,
                prefill: false,
            },
            &mut registry,
        );

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
        let pool = BufferPool::new(
            BufferPoolConfig {
                min_size: page,
                max_size: page,
                max_per_class: 2,
                prefill: false,
            },
            &mut registry,
        );

        let mut buf = pool.alloc(100).unwrap();
        buf.put_slice(b"hello world");

        let iobuf = buf.freeze();
        assert_eq!(iobuf.as_ref(), b"hello world");

        // IoBuf can be sliced
        let slice = iobuf.slice(0..5);
        assert_eq!(slice.as_ref(), b"hello");
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

    /// Test that PooledBufMut matches BytesMut behavior for Buf and BufMut traits.
    #[test]
    fn test_pooled_matches_bytesmut_behavior() {
        use bytes::BytesMut;

        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(
            BufferPoolConfig {
                min_size: page,
                max_size: page * 4,
                max_per_class: 10,
                prefill: false,
            },
            &mut registry,
        );

        // Create both buffer types
        let mut pooled = pool.alloc(100).unwrap();
        let mut bytes_mut = BytesMut::with_capacity(page);

        // Initially empty
        assert_eq!(pooled.len(), bytes_mut.len());
        assert_eq!(pooled.is_empty(), bytes_mut.is_empty());
        assert_eq!(Buf::remaining(&pooled), Buf::remaining(&bytes_mut));

        // Write some data using BufMut
        pooled.put_slice(b"hello world");
        bytes_mut.put_slice(b"hello world");

        assert_eq!(pooled.len(), bytes_mut.len());
        assert_eq!(pooled.as_ref(), bytes_mut.as_ref());
        assert_eq!(Buf::remaining(&pooled), Buf::remaining(&bytes_mut));
        assert_eq!(Buf::chunk(&pooled), Buf::chunk(&bytes_mut));

        // Advance (read cursor)
        Buf::advance(&mut pooled, 6);
        Buf::advance(&mut bytes_mut, 6);

        assert_eq!(pooled.len(), bytes_mut.len());
        assert_eq!(Buf::remaining(&pooled), Buf::remaining(&bytes_mut));
        assert_eq!(Buf::chunk(&pooled), Buf::chunk(&bytes_mut));
        assert_eq!(pooled.as_ref(), bytes_mut.as_ref());

        // Write more data
        pooled.put_slice(b"!");
        bytes_mut.put_slice(b"!");

        assert_eq!(pooled.len(), bytes_mut.len());
        assert_eq!(Buf::remaining(&pooled), Buf::remaining(&bytes_mut));
        assert_eq!(pooled.as_ref(), bytes_mut.as_ref());

        // Advance to end
        let remaining = Buf::remaining(&pooled);
        Buf::advance(&mut pooled, remaining);
        Buf::advance(&mut bytes_mut, remaining);

        assert_eq!(pooled.len(), 0);
        assert_eq!(bytes_mut.len(), 0);
        assert!(pooled.is_empty());
        assert!(bytes_mut.is_empty());

        // Freeze and compare
        let pooled_frozen = pooled.freeze();
        let bytes_frozen = bytes_mut.freeze();

        assert_eq!(pooled_frozen.as_ref(), bytes_frozen.as_ref());
        assert!(pooled_frozen.is_empty());
        assert!(bytes_frozen.is_empty());
    }

    /// Test that PooledBufMut freeze preserves only remaining data (after advance).
    #[test]
    fn test_pooled_freeze_after_advance() {
        use bytes::BytesMut;

        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(
            BufferPoolConfig {
                min_size: page,
                max_size: page,
                max_per_class: 10,
                prefill: false,
            },
            &mut registry,
        );

        let mut pooled = pool.alloc(100).unwrap();
        let mut bytes_mut = BytesMut::with_capacity(page);

        // Write data
        pooled.put_slice(b"hello world");
        bytes_mut.put_slice(b"hello world");

        // Advance past "hello "
        Buf::advance(&mut pooled, 6);
        Buf::advance(&mut bytes_mut, 6);

        // Freeze - should only contain "world"
        let pooled_frozen = pooled.freeze();
        let bytes_frozen = bytes_mut.freeze();

        assert_eq!(pooled_frozen.as_ref(), b"world");
        assert_eq!(pooled_frozen.as_ref(), bytes_frozen.as_ref());
    }

    /// Test clear resets both cursor and length.
    #[test]
    fn test_pooled_clear() {
        let page = page_size();
        let mut registry = test_registry();
        let pool = BufferPool::new(
            BufferPoolConfig {
                min_size: page,
                max_size: page,
                max_per_class: 10,
                prefill: false,
            },
            &mut registry,
        );

        let mut pooled = pool.alloc(100).unwrap();

        // Write and advance
        pooled.put_slice(b"hello world");
        Buf::advance(&mut pooled, 6);
        assert_eq!(pooled.len(), 5);

        // Clear should reset everything
        pooled.clear();
        assert_eq!(pooled.len(), 0);
        assert!(pooled.is_empty());

        // Can write again from the beginning
        pooled.put_slice(b"new data");
        assert_eq!(pooled.as_ref(), b"new data");
    }

    #[test]
    fn test_config_default() {
        let config = BufferPoolConfig::default();
        config.validate();
        assert_eq!(config.min_size, page_size());
        assert_eq!(config.max_size, 64 * 1024);
        assert_eq!(config.max_per_class, 64);
        assert!(config.prefill);
    }

    #[test]
    fn test_config_for_network() {
        let config = BufferPoolConfig::for_network();
        config.validate();
        assert_eq!(config.min_size, page_size());
        assert_eq!(config.max_size, 64 * 1024);
        assert_eq!(config.max_per_class, 64);
        assert!(config.prefill);
    }

    #[test]
    fn test_config_for_storage() {
        let config = BufferPoolConfig::for_storage();
        config.validate();
        assert_eq!(config.min_size, page_size());
        assert_eq!(config.max_size, 64 * 1024);
        assert_eq!(config.max_per_class, 32);
        assert!(config.prefill);
    }

    #[test]
    fn test_buffer_pools_with_defaults() {
        let mut registry = test_registry();
        let pools = BufferPools::with_defaults(&mut registry);

        // Verify network pool works
        let net_buf = pools.network().alloc(1024).expect("network alloc failed");
        assert!(net_buf.capacity() >= page_size());

        // Verify storage pool works
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
        assert_eq!(net_cfg.max_per_class, 64);

        let storage_cfg = pools.storage().config();
        assert_eq!(storage_cfg.max_per_class, 32);
    }
}
