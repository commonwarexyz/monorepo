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
//! Allocation and deallocation use atomic counters together with a bounded
//! lock-free global freelist plus per-thread caches.
//!
//! # Pool Lifecycle
//!
//! Tracked buffers held by pooled views or cached in thread-local bins keep a
//! strong reference to the originating size class. Buffers can outlive the
//! public [`BufferPool`] handle and still return to their original size class.
//! - Untracked fallback allocations store no class reference and deallocate
//!   directly when dropped.
//! - Requests smaller than [`BufferPoolConfig::pool_min_size`] bypass pooling
//!   entirely and return untracked aligned allocations from both
//!   [`BufferPool::try_alloc`] and [`BufferPool::alloc`].
//! - Dropping [`BufferPool`] drains only the shared global freelists, pooled
//!   views and buffers cached in a live thread's local cache can keep their
//!   size class alive until they are dropped or the thread exits.
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

use super::{freelist::Freelist, IoBufMut};
use crate::{
    iobuf::buffer::{PooledBufMut, PooledBuffer},
    telemetry::metrics::{raw, Counter, CounterFamily, EncodeLabelSet, GaugeFamily, Register},
};
use commonware_utils::{NZUsize, NZU32};
use crossbeam_utils::CachePadded;
use std::{
    alloc::Layout,
    cell::{Cell, UnsafeCell},
    mem::{align_of, MaybeUninit},
    num::{NonZeroU32, NonZeroUsize},
    ptr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

/// Minimum thread-local cache capacity required before refill/spill batches.
///
/// Below this threshold TLS still provides same-thread locality, but batching
/// would degrade to single-buffer moves and add policy complexity without
/// amortizing shared-queue traffic.
const MIN_TLS_BATCH_CAPACITY: usize = 4;

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
/// Matches the architecture-specific alignment used by
/// [`crossbeam_utils::CachePadded`].
const fn cache_line_size() -> usize {
    align_of::<CachePadded<u8>>()
}

/// Policy for sizing each thread's cache within a buffer pool size class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BufferPoolThreadCacheConfig {
    /// Enable thread-local caching.
    ///
    /// `None` derives the per-thread cache size from the pool's per-class
    /// capacity and expected parallelism, reserving about half of each class
    /// for the shared freelist. Small per-class budgets may resolve to zero,
    /// disabling thread-local caching so free buffers do not become stranded in
    /// other threads.
    ///
    /// `Some(n)` uses an exact per-thread cache size for every size class.
    Enabled(Option<NonZeroUsize>),
    /// Disable thread-local caching and route all reuse through the shared global freelist.
    Disabled,
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
    ///
    /// Size-class slots are identified by `u32`, so the per-class capacity is
    /// capped by this type.
    pub max_per_class: NonZeroU32,
    /// Whether to create every tracked buffer during pool construction.
    ///
    /// When enabled, each size class creates `max_per_class` buffers and parks
    /// them in the class-global freelist before the pool is returned. This
    /// moves allocation cost to startup and makes the first reuse path avoid
    /// heap allocation.
    pub prefill: bool,
    /// Buffer alignment. Must be a power of two.
    pub alignment: NonZeroUsize,
    /// Expected number of threads concurrently accessing the pool.
    ///
    /// This sizes the shared global freelist stripes. It is also used to derive
    /// thread-cache capacity when the thread-cache policy is automatic, using
    /// approximately half of [`Self::max_per_class`] divided across expected
    /// threads.
    pub parallelism: NonZeroUsize,
    /// Policy for sizing the per-thread local cache in each size class.
    ///
    /// By default, thread-cache capacity is derived from [`Self::parallelism`].
    /// [`Self::with_thread_cache_capacity`] uses an exact per-thread cache size.
    /// [`Self::with_thread_cache_disabled`] bypasses thread-local caches.
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
            max_per_class: NZU32!(4096),
            prefill: false,
            alignment: cache_line,
            parallelism: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::Enabled(None),
        }
    }

    /// Storage I/O preset: page-aligned, page_size to 8MB buffers, 64 per class,
    /// not prefilled.
    ///
    /// Page alignment is required for direct I/O and efficient DMA transfers.
    pub fn for_storage() -> Self {
        let page = NZUsize!(page_size());
        Self {
            pool_min_size: 1024,
            min_size: page,
            max_size: NZUsize!(8 * 1024 * 1024),
            max_per_class: NZU32!(64),
            prefill: false,
            alignment: page,
            parallelism: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::Enabled(None),
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
    pub const fn with_max_per_class(mut self, max_per_class: NonZeroU32) -> Self {
        self.max_per_class = max_per_class;
        self
    }

    /// Returns a copy of this config with a new expected parallelism.
    ///
    /// This controls the minimum global-freelist stripe count, and controls
    /// thread-cache capacity when the thread-cache policy is automatic. The
    /// automatic policy reserves about half of each class for the global
    /// freelist and divides the remaining capacity across expected threads.
    pub const fn with_parallelism(mut self, parallelism: NonZeroUsize) -> Self {
        self.parallelism = parallelism;
        self
    }

    /// Returns a copy of this config with an explicit per-thread cache size.
    ///
    /// Global-freelist striping is set separately by [`Self::with_parallelism`].
    pub const fn with_thread_cache_capacity(mut self, thread_cache_capacity: NonZeroUsize) -> Self {
        self.thread_cache_config =
            BufferPoolThreadCacheConfig::Enabled(Some(thread_cache_capacity));
        self
    }

    /// Returns a copy of this config with thread-local caching disabled.
    ///
    /// Global-freelist striping is set separately by [`Self::with_parallelism`].
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
    ///
    /// # Panics
    ///
    /// - `min_size` is not a power of two
    /// - `max_size` is not a power of two
    /// - `max_size < min_size`
    /// - the derived per-class capacity does not fit in `u32`.
    pub fn with_budget_bytes(mut self, budget_bytes: NonZeroUsize) -> Self {
        self.validate_size_class_bounds();

        let mut class_bytes = 0usize;
        let min_size = self.min_size.get();
        for i in 0..Self::num_classes(min_size, self.max_size.get()) {
            class_bytes = class_bytes.saturating_add(Self::class_size(min_size, i));
        }
        if class_bytes == 0 {
            return self;
        }
        let max_per_class = u32::try_from(budget_bytes.get().div_ceil(class_bytes))
            .expect("max_per_class must fit in u32 slot ids");
        self.max_per_class =
            NonZeroU32::new(max_per_class).expect("max_per_class must be non-zero");
        self
    }

    /// Validates the size-class bounds, panicking on invalid values.
    ///
    /// # Panics
    ///
    /// - `min_size` is not a power of two
    /// - `max_size` is not a power of two
    /// - `max_size < min_size`
    fn validate_size_class_bounds(&self) {
        let min_size = self.min_size.get();
        let max_size = self.max_size.get();

        assert!(
            min_size.is_power_of_two(),
            "min_size must be a power of two"
        );
        assert!(
            max_size.is_power_of_two(),
            "max_size must be a power of two"
        );
        assert!(max_size >= min_size, "max_size must be >= min_size");
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
        self.validate_size_class_bounds();
        assert!(
            self.alignment.is_power_of_two(),
            "alignment must be a power of two"
        );
        assert!(
            self.min_size >= self.alignment,
            "min_size ({}) must be >= alignment ({})",
            self.min_size,
            self.alignment
        );
        assert!(
            self.pool_min_size <= self.min_size.get(),
            "pool_min_size ({}) must be <= min_size ({})",
            self.pool_min_size,
            self.min_size
        );
        if let BufferPoolThreadCacheConfig::Enabled(Some(thread_cache_capacity)) =
            self.thread_cache_config
        {
            assert!(
                thread_cache_capacity.get() <= self.max_per_class.get() as usize,
                "thread_cache_capacity ({}) must be <= max_per_class ({})",
                thread_cache_capacity,
                self.max_per_class
            );
        }
    }

    /// Returns the number of size classes between validated bounds.
    #[inline]
    const fn num_classes(min_size: usize, max_size: usize) -> usize {
        // Since sizes are powers of two, trailing zeros is the size-class
        // exponent
        (max_size.trailing_zeros() - min_size.trailing_zeros() + 1) as usize
    }

    /// Returns the buffer size for a validated size-class index.
    #[inline]
    const fn class_size(min_size: usize, index: usize) -> usize {
        min_size << index
    }

    /// Resolves the effective per-thread cache size for each size class.
    ///
    /// Derived capacities divide half of the class budget across the expected
    /// parallelism so cross-thread reuse remains effective. Small class budgets
    /// may resolve to zero.
    fn resolve_thread_cache_capacity(&self) -> usize {
        match self.thread_cache_config {
            BufferPoolThreadCacheConfig::Enabled(None) => {
                let max_per_class = self.max_per_class.get() as usize;
                let effective_threads = self.parallelism.get().min(max_per_class);
                max_per_class / (2 * effective_threads)
            }
            BufferPoolThreadCacheConfig::Enabled(Some(thread_cache_capacity)) => {
                thread_cache_capacity.get()
            }
            BufferPoolThreadCacheConfig::Disabled => 0,
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
    /// Number of tracked buffers created for the size class.
    created: GaugeFamily<SizeClassLabel>,
    /// Total number of failed allocations (pool exhausted).
    exhausted_total: CounterFamily<SizeClassLabel>,
    /// Total number of oversized allocation requests.
    oversized_total: Counter,
}

impl PoolMetrics {
    fn new(registry: &mut impl Register) -> Self {
        Self {
            created: registry.register(
                "buffer_pool_created",
                "Number of tracked buffers created for the pool",
                raw::Family::default(),
            ),
            exhausted_total: registry.register(
                "buffer_pool_exhausted_total",
                "Total number of failed allocations due to pool exhaustion",
                raw::Family::default(),
            ),
            oversized_total: registry.register(
                "buffer_pool_oversized_total",
                "Total number of allocation requests exceeding max buffer size",
                raw::Counter::default(),
            ),
        }
    }
}

/// Per-size-class state.
///
/// Each class is a small two-level allocator:
/// - a shared global freelist for tracked buffers visible to all threads
/// - a per-thread local cache for same-thread reuse
///
/// The global freelist owns the allocation layout, slot reservation counter,
/// and parking cells for this class. A tracked buffer can be globally parked,
/// owned by a pooled backing, or parked in one thread's local cache, but the
/// slot always belongs to this `SizeClass`.
///
/// Liveness follows the buffer ownership state. Global freelist entries rely on
/// the pool's [`SizeClassHandle`] while the pool is alive and are drained when
/// the pool is dropped. Pooled backing values carry a [`SizeClassLease`].
/// Thread-local cache entries use banked strong references owned by the cache.
/// Those non-global states are what allow a buffer to outlive the public
/// [`BufferPool`] handle and still return to the correct freelist.
///
/// The freelist is the only place that deallocates tracked buffers. Returning a
/// buffer to the freelist transfers buffer ownership back to that freelist and
/// releases the pooled-backing lease or banked strong reference that kept the
/// class alive while the buffer was outside the global freelist.
///
/// Allocation prefers the local cache, then refills from the global freelist,
/// and only creates a new tracked buffer when no free buffer is available and
/// the class still has remaining capacity.
pub(super) struct SizeClass {
    /// Dense global identifier for the TLS cache registry.
    class_id: usize,
    /// The buffer size for this class.
    size: usize,
    /// Global free list of tracked buffers available for reuse.
    global: Freelist,
    /// Maximum number of buffers retained in the current thread's local bin.
    thread_cache_capacity: usize,
}

// SAFETY: shared state in `SizeClass` is synchronized through atomics and the
// global free set. Per-thread bins are stored in thread-local registries and only
// accessed by the current thread.
unsafe impl Send for SizeClass {}
// SAFETY: see above.
unsafe impl Sync for SizeClass {}

/// Non-owning raw identity for a size class.
///
/// # Size-class lifetime model
///
/// A [`SizeClass`] owns the [`Freelist`] for one buffer size class. The
/// freelist creates tracked [`PooledBuffer`]s, owns the allocation layout
/// needed to deallocate them, and is the only place that releases their memory.
/// A `PooledBuffer` outside the freelist does not carry enough information to
/// deallocate itself, so it must keep its originating `SizeClass` alive until
/// it can return to that freelist.
///
/// The pool has three buffer states, and those states determine where the
/// strong size-class references live.
///
/// - Global freelist: the buffer is parked in [`SizeClass::global`] and carries
///   no per-buffer strong reference. While the public pool exists, the
///   [`SizeClassHandle`] in [`BufferPoolInner::classes`] keeps the class alive.
/// - Pooled view: the buffer is owned by mutable or immutable I/O view state
///   and carries one [`SizeClassLease`], which is one strong reference to the
///   class.
/// - Thread-local cache: the [`TlsSizeClassCache`] stores the
///   [`SizeClassToken`] once, and owns one banked strong reference for each
///   initialized [`TlsSizeClassCacheEntry`]. A banked reference is an owned
///   `Arc<SizeClass>` reference counted by TLS cache state instead of
///   represented by a `SizeClassLease` value in each entry. Increasing `len`
///   banks one reference, decreasing `len` transfers one reference back into a
///   `SizeClassLease` or releases it to the global freelist.
///
/// Moving a buffer from the global freelist to pooled view or TLS state retains
/// one class reference. Moving it back to the global freelist releases that
/// reference. Moving between pooled view and TLS state transfers the same
/// reference without touching the refcount.
///
/// Dropping the public [`BufferPool`] drains globally parked buffers, then
/// drops its `SizeClassHandle`s. Pooled views and non-empty TLS caches may keep
/// the `SizeClass` alive after that point. Empty TLS caches may still remember
/// a token value, but with no banked references that token is only an inert
/// identity value and must not be dereferenced.
///
/// This is the one raw pointer shape used by all pool-owned, pooled view, and
/// thread-local references to a [`SizeClass`]. The pointer is always derived
/// from [`Arc::into_raw`].
///
/// `SizeClassToken` itself owns nothing. It is only an identity token and raw
/// pointer accepted by the `Arc` refcount APIs:
/// - [`SizeClassHandle`] pairs a token with ownership of one strong reference.
/// - [`SizeClassLease`] pairs a token with ownership of one strong reference.
/// - [`TlsSizeClassCache`] stores a token plus `len` banked strong references.
///
/// Because the token is non-owning, it may be stale when held by an empty TLS
/// cache. Code may dereference it or adjust the strong count only when another
/// invariant proves the allocation is still live. For example, a
/// [`SizeClassHandle`] proves liveness through its owned strong reference, and
/// a non-empty [`TlsSizeClassCache`] proves liveness through its banked
/// entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SizeClassToken {
    ptr: ptr::NonNull<SizeClass>,
}

impl SizeClassToken {
    /// Creates a token and owns the initial strong reference for `class`.
    ///
    /// The returned token is non-owning in the type system, but the raw pointer
    /// still represents one strong reference. The caller must wrap it in an
    /// owning type, such as [`SizeClassHandle`], or otherwise arrange for that
    /// strong reference to be released.
    fn new(class: SizeClass) -> Self {
        let ptr = Arc::into_raw(Arc::new(class)).cast_mut();
        // SAFETY: `Arc::into_raw` never returns null.
        let ptr = unsafe { ptr::NonNull::new_unchecked(ptr) };
        Self { ptr }
    }

    /// Returns the referenced size class.
    ///
    /// # Safety
    ///
    /// Some owner must currently hold a strong reference for this token.
    #[inline(always)]
    const unsafe fn as_ref(&self) -> &SizeClass {
        // SAFETY: guaranteed by the caller.
        unsafe { self.ptr.as_ref() }
    }

    /// Retains one strong reference for this token.
    ///
    /// # Safety
    ///
    /// Some owner must currently hold a strong reference for this token.
    #[inline(always)]
    unsafe fn retain(self) {
        // SAFETY: guaranteed by the caller.
        unsafe { Arc::increment_strong_count(self.ptr.as_ptr()) };
    }

    /// Releases one owned strong reference for this token.
    ///
    /// # Safety
    ///
    /// The caller must own one strong reference represented by this token.
    #[inline(always)]
    unsafe fn release(self) {
        // SAFETY: guaranteed by the caller.
        unsafe { Arc::decrement_strong_count(self.ptr.as_ptr()) };
    }
}

/// Owning pool reference to a size class.
///
/// This is the pool's strong `Arc<SizeClass>` reference represented by a
/// [`SizeClassToken`]. `SizeClassHandle` is the long-lived owner for a class
/// while the [`BufferPoolInner`] exists. Dropping the handle releases that
/// pool-owned strong reference. A class may still outlive the handle if pooled
/// backing values or thread-local cache entries own additional references
/// through [`SizeClassLease`] or banked TLS refs.
///
/// Functionally this is an `Arc<SizeClass>` stored in raw-token form. It exists
/// to keep the pool-owned reference alive and to provide a live token for
/// allocation paths that need to retain pooled-backing or TLS-banked
/// references. The raw form keeps the already-loaded class pointer usable for
/// explicit refcount operations without calling [`Arc::as_ptr`] or storing a
/// second token alongside an `Arc`.
struct SizeClassHandle {
    token: SizeClassToken,
}

// SAFETY: `SizeClassHandle` owns a strong reference to a `SizeClass`, which is
// `Send`.
unsafe impl Send for SizeClassHandle {}
// SAFETY: same argument as `Send`, shared access to `SizeClass` is synchronized.
unsafe impl Sync for SizeClassHandle {}

impl SizeClassHandle {
    /// Creates a new size class and takes ownership of its initial strong ref.
    ///
    /// If `prefill` is true, the global freelist creates `max` buffers upfront
    /// and makes them immediately available for reuse.
    fn new(
        class_id: usize,
        size: usize,
        alignment: usize,
        max: NonZeroU32,
        parallelism: NonZeroUsize,
        thread_cache_capacity: usize,
        prefill: bool,
    ) -> Self {
        let layout = Layout::from_size_align(size, alignment).expect("alignment is a power of two");
        let freelist = Freelist::new(max, parallelism, layout, prefill);
        let class = SizeClass {
            class_id,
            size,
            global: freelist,
            thread_cache_capacity,
        };
        Self {
            token: SizeClassToken::new(class),
        }
    }

    /// Creates a new tracked buffer and retains this size class for its slot.
    #[inline(always)]
    fn try_create(&self, zeroed: bool) -> Option<(u32, PooledBuffer, SizeClassLease)> {
        let (slot, buffer) = self.global.try_create(zeroed)?;
        let class = SizeClassLease::retain(self);
        Some((slot, buffer, class))
    }
}

impl Drop for SizeClassHandle {
    fn drop(&mut self) {
        // SAFETY: this handle owns one strong reference for `self.token`.
        unsafe { self.token.release() };
    }
}

impl std::ops::Deref for SizeClassHandle {
    type Target = SizeClass;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        // SAFETY: this handle owns one strong reference for `self.token`.
        unsafe { self.token.as_ref() }
    }
}

/// Owned size-class reference for a pooled buffer outside the global freelist.
///
/// A pooled buffer outside the global freelist must keep its originating
/// [`SizeClass`] alive so it can be returned after the [`BufferPool`] handle is
/// dropped. This is one strong `Arc<SizeClass>` reference represented by a
/// [`SizeClassToken`], with retain and release performed explicitly at the
/// boundaries where a buffer enters or leaves global pool state.
///
/// Lifetime-wise this is the same kind of reference as [`SizeClassHandle`]:
/// both own exactly one strong reference for a token. The types are separate
/// because they live in different state machines. `SizeClassHandle` is ordinary
/// RAII ownership for the pool's class vector. `SizeClassLease` is hot-path
/// pooled view ownership that must be explicitly transferred into TLS cache
/// state or returned to the global freelist.
///
/// The raw representation matters because the hot path mostly transfers
/// ownership between pooled view state and this thread's local cache. A real
/// `Arc<SizeClass>` field is pointer-sized too, but it is a non-`Copy` value
/// with drop glue. Even when the strong count would not change, moving it
/// through pooled buffer and cache-entry structs makes the compiler preserve
/// destructor paths for those structs. `SizeClassLease` has no automatic drop:
/// moving between pooled view and local-cache state is a plain pointer
/// transfer, and only explicit calls such as [`Self::return_global`] adjust the
/// strong count.
///
/// A lease must be consumed by one of those explicit transitions, such as
/// [`Self::into_banked`] or [`Self::return_global`]. Because this type
/// intentionally has no `Drop` implementation, simply dropping a lease value
/// would leak the strong reference. This keeps hot transfers free of drop glue,
/// but means every owner must complete one of the explicit transitions.
///
/// Thread-local cache entries do not store a lease per entry. The cache stores
/// the class token once and owns one banked strong reference for each
/// initialized entry. Popping from the local cache materializes a lease from
/// one of those banked references without touching the strong count.
///
/// Globally parked buffers do not carry a class reference: taking from the
/// global freelist retains the class, and returning to the global freelist
/// releases it.
#[must_use]
pub(crate) struct SizeClassLease {
    token: SizeClassToken,
}

// SAFETY: `SizeClassLease` owns one strong reference to a `SizeClass`, which is
// `Send`.
unsafe impl Send for SizeClassLease {}
// SAFETY: same argument as `Send`, shared access to `SizeClass` is synchronized.
unsafe impl Sync for SizeClassLease {}

impl SizeClassLease {
    /// Converts one banked class reference into a lease.
    ///
    /// This does not retain the class. It only changes how an already-owned
    /// strong reference is represented: from TLS cache state into a
    /// `SizeClassLease` value.
    ///
    /// # Safety
    ///
    /// The caller must own one banked strong reference for `class.token`, and
    /// that retained reference must be transferred to the returned lease. This
    /// must not consume the pool-owned reference held by `class` itself.
    #[inline(always)]
    const unsafe fn from_banked(class: &SizeClassHandle) -> Self {
        Self { token: class.token }
    }

    /// Retains `class` for a buffer leaving the global freelist.
    #[inline(always)]
    fn retain(class: &SizeClassHandle) -> Self {
        let token = class.token;
        // SAFETY: the borrowed `class` owns one strong reference for `token`.
        unsafe { token.retain() };
        Self { token }
    }

    /// Transfers this lease into a TLS cache entry.
    ///
    /// This does not release the class. It consumes the lease and relies on the
    /// caller to record one additional banked reference in TLS cache state,
    /// normally by storing an entry and increasing the cache length. The cache
    /// must later materialize or release exactly one lease for that entry.
    ///
    /// This is a no-op at runtime, it exists to mark the ownership transition.
    #[inline(always)]
    const fn into_banked(self) {}

    /// Returns the referenced size class.
    ///
    /// The token is valid because `SizeClassLease` owns one strong reference.
    #[inline(always)]
    const fn class(&self) -> &SizeClass {
        // SAFETY: guaranteed by the ownership invariant documented on
        // `SizeClassLease`.
        unsafe { self.token.as_ref() }
    }

    /// Returns the buffer size for this lease's size class.
    #[inline(always)]
    pub(crate) const fn size(&self) -> usize {
        self.class().size
    }

    /// Returns a buffer to this class's global freelist and releases the class
    /// reference.
    ///
    /// The buffer is parked before the strong reference is released. If this is
    /// the last outstanding reference after the public pool has been dropped,
    /// dropping the `SizeClass` will then drain the just-parked buffer.
    #[inline(always)]
    fn return_global(self, slot: u32, buffer: PooledBuffer) {
        self.class().global.put(slot, buffer);
        // SAFETY: this lease owns one strong reference.
        unsafe { self.token.release() };
    }
}

/// Free tracked buffer owned by a thread-local size-class cache.
///
/// This is allocator cache state, not a caller-visible pooled view. While an
/// entry is held here, the buffer is owned by the current thread and is not
/// visible to the class-global freelist.
///
/// The `slot` identifies the buffer within its [`SizeClass`]. The enclosing
/// cache owns one banked size-class reference for this entry. The entry itself
/// intentionally stores only `(buffer, slot)` so local pop/push does not move a
/// class pointer per buffer.
struct TlsSizeClassCacheEntry {
    buffer: PooledBuffer,
    slot: u32,
}

/// Per-thread cache for one size class's tracked buffers.
///
/// Each instance is stored in [`TlsSizeClassCaches`] under one global
/// [`SizeClass::class_id`], so all entries in the cache belong to the same size
/// class. The cache owns full [`PooledBuffer`] values while they are local,
/// returning them to the global freelist happens only on miss refill, overflow,
/// explicit flush, or thread exit.
///
/// `class` is a non-owning token for this cache's size class. It can be stale
/// while `len == 0`, because an empty cache does not keep its pool alive. When
/// `len > 0`, each initialized entry in `entries[..len]` owns one banked
/// size-class reference, which keeps the pointed-to class alive. The entry
/// itself stays small (`buffer, slot`), popping it materializes a
/// [`SizeClassLease`] from one banked reference.
///
/// As described in [`SizeClassToken`], a banked reference is represented by
/// cache state rather than by a value stored in the entry. Changing `len` is
/// therefore an ownership transition as well as a stack operation.
///
/// An empty cache may keep a stale token only for identity checks. It must not
/// dereference the token or adjust its strong count until a live
/// [`SizeClassHandle`] or banked entry proves the class is still alive.
///
/// The hot steady-state allocation path pops an entry from `entries`, and the
/// hot return path pushes one back while there is room.
struct TlsSizeClassCache {
    class: SizeClassToken,
    entries: Box<[MaybeUninit<TlsSizeClassCacheEntry>]>,
    len: usize,
    capacity: usize,
}

impl TlsSizeClassCache {
    /// Creates a new empty cache with the given maximum thread-cache size.
    ///
    /// The cache stores `class.token` for identity, but starts with `len == 0`
    /// and therefore owns no banked size-class references.
    fn new(class: &SizeClassHandle, capacity: usize) -> Self {
        let entries = (0..capacity)
            .map(|_| MaybeUninit::uninit())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            class: class.token,
            entries,
            len: 0,
            capacity,
        }
    }

    /// Removes and returns one reusable buffer entry.
    ///
    /// Local hits are served directly from the cache. On a local miss, small
    /// caches take only the buffer being returned to the caller. Larger caches
    /// batch-take from the global freelist, return the first claimed buffer,
    /// and retain the rest locally for future allocations.
    ///
    /// The returned lease is materialized from the banked size-class reference
    /// associated with the returned entry.
    #[inline(always)]
    fn pop(&mut self, class: &SizeClassHandle) -> Option<(TlsSizeClassCacheEntry, SizeClassLease)> {
        if let Some(entry) = self.pop_local() {
            // SAFETY: the popped entry consumed one banked reference owned by
            // this cache. Transfer that reference to the returned lease.
            let lease = unsafe { SizeClassLease::from_banked(class) };
            return Some((entry, lease));
        }

        // Take from the class-global freelist on a local miss.
        self.pop_global(class)
    }

    /// Removes and returns one entry from this thread's local stack.
    ///
    /// This touches only thread-local cache state. A returned entry consumes
    /// one banked size-class reference from this cache, the caller must
    /// materialize or release that reference.
    #[inline(always)]
    fn pop_local(&mut self) -> Option<TlsSizeClassCacheEntry> {
        if self.len == 0 {
            return None;
        }

        self.len -= 1;
        // SAFETY: entries in `0..self.len` are initialized. Decrementing `len`
        // above makes this slot uninitialized again.
        Some(unsafe { self.entries.get_unchecked(self.len).assume_init_read() })
    }

    /// Takes from the class-global freelist after the local stack misses.
    ///
    /// Every claimed global entry gets one retained class reference. The first
    /// claimed entry is returned with that reference materialized as a
    /// [`SizeClassLease`], additional claimed entries are parked in this cache
    /// and counted by `len`.
    ///
    /// This is separate from [`Self::pop`] so the steady-state allocation hot
    /// path can inline only the local cache hit. We annotate with `inline(never)`
    /// to keep the refill and batching code out of `BufferPoolInner::try_alloc`,
    /// reducing hot-path code size and register pressure.
    #[inline(never)]
    fn pop_global(
        &mut self,
        class: &SizeClassHandle,
    ) -> Option<(TlsSizeClassCacheEntry, SizeClassLease)> {
        // Tiny caches do not batch enough to justify the wider global claim.
        // Keep their miss path equivalent to a single take.
        if self.capacity < MIN_TLS_BATCH_CAPACITY {
            return class.global.take().map(|(slot, buffer)| {
                let lease = SizeClassLease::retain(class);
                (TlsSizeClassCacheEntry { buffer, slot }, lease)
            });
        }

        // Refill larger caches to half capacity. That leaves room for future
        // same-thread returns while still amortizing the global atomic scan
        // over several future local pops.
        let mut entry = None;
        let take = self.capacity / 2;
        class.global.take_batch(take, |slot, buffer| {
            // Each claimed global entry becomes either the returned lease or a
            // local cache entry, so each needs one retained class reference.
            //
            // SAFETY: the borrowed `class` owns one strong reference for its
            // token while the refill runs.
            unsafe { class.token.retain() };
            let cache_entry = TlsSizeClassCacheEntry { buffer, slot };
            if entry.is_none() {
                // Hand the first claimed buffer to the allocation that missed
                // locally. Additional claimed buffers refill the local cache.
                //
                // SAFETY: `class.token.retain()` above retained the strong
                // reference transferred to this returned lease.
                let lease = unsafe { SizeClassLease::from_banked(class) };
                entry = Some((cache_entry, lease));
            } else {
                // The take count is derived from the target occupancy, so
                // refill cannot overflow the local cache. Push directly to
                // avoid the spill checks used by return-to-cache.
                self.push_local(cache_entry);
            }
        });

        entry
    }

    /// Pushes an entry into the local cache, spilling to global if full.
    ///
    /// Small local caches prioritize same-thread locality and route overflow
    /// directly to the global freelist. Once the local cache is large enough to
    /// batch effectively, half the entries are drained to amortize global queue
    /// traffic across future returns.
    #[inline(always)]
    fn push(&mut self, class: SizeClassLease, slot: u32, buffer: PooledBuffer) {
        let entry = TlsSizeClassCacheEntry { buffer, slot };

        if self.len < self.capacity {
            // The returned lease becomes one banked reference represented by
            // the new local stack entry.
            class.into_banked();
            self.push_local(entry);
            return;
        }

        // Handle overflow when the local stack is full.
        self.push_full(class, entry);
    }

    /// Pushes one entry onto this thread's local stack.
    ///
    /// The caller must ensure the stack has room and must transfer one
    /// size-class reference into banked local-cache ownership.
    #[inline(always)]
    fn push_local(&mut self, entry: TlsSizeClassCacheEntry) {
        // SAFETY: the caller ensured `self.len < self.capacity`, so this slot
        // is in bounds and currently uninitialized.
        unsafe {
            self.entries.get_unchecked_mut(self.len).write(entry);
        }
        self.len += 1;
    }

    /// Handles a push after the local stack fills.
    ///
    /// Very small caches return the incoming entry directly to the global
    /// freelist. Larger caches spill older local entries in a batch, then keep
    /// the incoming entry local so the dropping thread retains the freshest
    /// buffer.
    ///
    /// This is separate from [`Self::push`] so the steady-state return hot path
    /// can inline only the local cache push. We annotate with `inline(never)`
    /// to keep the spill and batching code out of pooled buffer drop when the
    /// local cache has room.
    #[inline(never)]
    fn push_full(&mut self, class: SizeClassLease, entry: TlsSizeClassCacheEntry) {
        // Very small caches cannot spill enough entries to amortize a batch
        // insert, so overflow goes straight to the global freelist.
        if self.capacity < MIN_TLS_BATCH_CAPACITY {
            class.return_global(entry.slot, entry.buffer);
            return;
        }

        // Spill half the cache to global to make room.
        let spill = self.len.min(self.capacity / 2).max(1);
        let end = self.len;
        let start = end - spill;
        // Stop tracking slots before moving them out.
        self.len = start;

        class
            .class()
            .global
            .put_batch((start..end).rev().map(|index| {
                // SAFETY: `start..end` was initialized before `len` was lowered
                // to `start`. Reading each slot moves it out and leaves the
                // slot uninitialized.
                let entry = unsafe { self.entries.as_mut_ptr().add(index).read().assume_init() };
                // SAFETY: this drained entry carried one banked reference. The
                // incoming `class` lease keeps the size class live while
                // `put_batch` parks the spilled entries.
                unsafe { self.class.release() };
                (entry.slot, entry.buffer)
            }));

        // The incoming lease becomes one banked reference represented by the
        // new local stack entry.
        class.into_banked();
        self.push_local(entry);
    }
}

impl Drop for TlsSizeClassCache {
    fn drop(&mut self) {
        let count = self.len;
        if count == 0 {
            return;
        }

        let class = self.class;
        let end = self.len;
        self.len = 0;
        let entries = self.entries.as_mut_ptr();
        {
            let entries = (0..end).rev().map(move |index| {
                // SAFETY: `0..end` was initialized before `len` was reset to 0.
                // Reading each slot moves it out and leaves the slot
                // uninitialized.
                let entry = unsafe { entries.add(index).read().assume_init() };
                (entry.slot, entry.buffer)
            });
            // SAFETY: each initialized entry carries one banked class reference
            // out of this cache. Because `count > 0`, those references keep
            // `class` live while the entries are parked.
            unsafe { class.as_ref() }.global.put_batch(entries);
        }
        for _ in 0..count {
            // SAFETY: each drained entry was returned to the global freelist, so
            // its banked reference can be released.
            unsafe { class.release() };
        }
    }
}

/// Registry of one thread's per-size-class caches.
///
/// A [`BufferPool`] keeps its size classes in a vector, so allocation resolves
/// a request to an index within that pool. Thread-local caches need a different
/// key because a thread can use more than one pool. They use the process-global
/// [`SizeClass::class_id`] assigned by [`NEXT_SIZE_CLASS_ID`], so index `0` in
/// one pool cannot collide with index `0` in another pool.
///
/// The registry is a sparse vector indexed by `class_id`. Each initialized
/// entry is a [`TlsSizeClassCache`] for that global size class. Missing entries
/// mean this thread has not used that size class yet. Holes can remain for the
/// lifetime of the thread because class ids are monotonic and never reused.
/// Empty initialized caches can also remain after their pool has been dropped,
/// their class token is inert while the cache is empty. If the class is still
/// live because a pooled buffer is outstanding, a later return of that buffer
/// to this same thread can bank a fresh reference and make the cache usable
/// again.
///
/// We intentionally use `Vec<Option<...>>` because class ids are dense enough
/// for direct indexing to be cheaper than hashing, but a thread may initialize
/// only a subset of live size classes. This keeps the TLS-hit path to a bounds
/// check and an initialized-entry check, with no synchronization.
struct TlsSizeClassCaches {
    bins: Vec<Option<TlsSizeClassCache>>,
}

impl TlsSizeClassCaches {
    /// Creates an empty registry.
    const fn new() -> Self {
        Self { bins: Vec::new() }
    }

    /// Returns the cache for `class`, creating it lazily on first use.
    ///
    /// A missing cache is initialized from the live `class` handle. An existing
    /// empty cache may contain a stale token from an older pool drop, but class
    /// ids are never reused, so an existing entry for this `class_id` can only
    /// refer to the same size class.
    #[inline(always)]
    fn get_or_init(&mut self, class: &SizeClassHandle) -> &mut TlsSizeClassCache {
        let class_id = class.class_id;
        if class_id < self.bins.len() && self.bins[class_id].is_some() {
            return self.bins[class_id]
                .as_mut()
                .expect("class cache was checked as initialized");
        }

        self.init(class)
    }

    /// Initializes and returns the cache for `class_id`.
    ///
    /// This is separate from [`Self::get_or_init`] so the steady-state TLS hit
    /// can inline only the existing-cache lookup. We annotate with
    /// `inline(never)` to keep the resize and allocation path out of pooled
    /// allocation and drop.
    #[inline(never)]
    fn init(&mut self, class: &SizeClassHandle) -> &mut TlsSizeClassCache {
        let class_id = class.class_id;
        if class_id >= self.bins.len() {
            self.bins.resize_with(class_id + 1, || None);
        }
        self.bins[class_id]
            .get_or_insert_with(|| TlsSizeClassCache::new(class, class.thread_cache_capacity))
    }

    /// Returns an initialized cache without creating a missing one.
    ///
    /// This is used on the drop path. If the dropping thread never allocated
    /// from this size class, returning the buffer to the global freelist avoids
    /// creating thread-local state from arbitrary destructor code.
    #[inline(always)]
    fn get(&mut self, class_id: usize) -> Option<&mut TlsSizeClassCache> {
        self.bins.get_mut(class_id).and_then(Option::as_mut)
    }
}

impl Drop for TlsSizeClassCaches {
    fn drop(&mut self) {
        let this = self as *mut Self;
        BufferPoolThreadCache::TLS_SIZE_CLASS_CACHES_FAST.with(|fast| {
            if fast.get() == this {
                fast.set(ptr::null_mut());
            }
        });
    }
}

/// Access to the calling thread's local [`BufferPool`] caches.
///
/// This type hides the TLS layout used by pooled allocation and return. The
/// main TLS key owns the registry. It has a destructor, so thread exit drops
/// the registry and each `TlsSizeClassCache` flushes its remaining entries to
/// the class-global freelist.
///
/// Rust's access path for TLS values with destructors includes checks for
/// access during or after destruction. Those checks are correct, but they are
/// expensive on the hot pooled allocation/drop path. After first checked
/// access, we cache a raw pointer to the same registry in a destructor-free TLS
/// key and use that pointer for steady-state access.
///
/// If the checked key is unavailable during thread-local destruction, cache
/// access returns `None` and callers use the class-global freelist instead.
pub struct BufferPoolThreadCache;

impl BufferPoolThreadCache {
    thread_local! {
        // Owns this thread's cache registry and drops it during thread exit.
        static TLS_SIZE_CLASS_CACHES: UnsafeCell<TlsSizeClassCaches> =
            const { UnsafeCell::new(TlsSizeClassCaches::new()) };

        // Performance-only pointer to the same registry. This key has no
        // destructor, so the hot allocation/drop path avoids Rust's
        // destructor-aware access path for `TLS_SIZE_CLASS_CACHES`.
        static TLS_SIZE_CLASS_CACHES_FAST: Cell<*mut TlsSizeClassCaches> =
            const { Cell::new(ptr::null_mut()) };
    }

    /// Flushes all local caches for the current thread into the global freelists.
    pub fn flush() {
        // If the owning TLS registry is unavailable during thread exit, this
        // is a no-op. The registry's own drop path will flush any remaining
        // entries.
        let _ = Self::TLS_SIZE_CLASS_CACHES.try_with(|caches| {
            // SAFETY: this TLS value is only ever accessed by the current thread.
            let caches = unsafe { &mut *caches.get() };
            for cache in caches.bins.iter_mut() {
                let _ = cache.take();
            }
        });
    }

    /// Returns a buffer to the current thread's local cache for the given
    /// size class, spilling to the global freelist if the cache is full.
    ///
    /// This only uses an already-initialized local cache. If the current thread
    /// has not initialized this size class, the buffer goes to the global
    /// freelist rather than creating local state from a drop path.
    #[inline(always)]
    pub(super) fn push(class: SizeClassLease, slot: u32, buffer: PooledBuffer) {
        let (class_id, thread_cache_capacity) = {
            let class_ref = class.class();
            (class_ref.class_id, class_ref.thread_cache_capacity)
        };

        if thread_cache_capacity == 0 {
            class.return_global(slot, buffer);
            return;
        }

        // Returning a pooled buffer can happen from arbitrary Drop code,
        // including during thread-local destruction. If the local cache is
        // unavailable, fall back to the global freelist instead of panicking.
        let caches = Self::TLS_SIZE_CLASS_CACHES_FAST.with(|fast| fast.get());
        if !caches.is_null() {
            // SAFETY: the fast pointer is set only from this thread's
            // `TLS_SIZE_CLASS_CACHES` value and cleared before that value
            // drops.
            if let Some(cache) = unsafe { (&mut *caches).get(class_id) } {
                cache.push(class, slot, buffer);
                return;
            }
        }

        class.return_global(slot, buffer);
    }

    /// Takes a buffer from the current thread's local cache for the given
    /// size class, refilling from the global freelist if the cache is empty.
    ///
    /// The local cache is checked first. On a local miss, the global freelist
    /// is queried once. The first claimed buffer is returned to the caller, and
    /// any additional claimed buffers are appended directly to the local cache.
    #[inline(always)]
    fn pop(class: &SizeClassHandle) -> Option<(PooledBuffer, SizeClassLease, u32)> {
        if class.thread_cache_capacity == 0 {
            return class
                .global
                .take()
                .map(|(slot, buffer)| (buffer, SizeClassLease::retain(class), slot));
        }

        // Allocation can happen from caller-owned TLS destructors during thread
        // teardown. If the local cache is unavailable, fall back to the global
        // freelist instead of panicking.
        #[allow(clippy::option_if_let_else)]
        match Self::cache(class) {
            Some(mut cache) => {
                // SAFETY: `cache` points to this thread's initialized TLS cache.
                unsafe { cache.as_mut().pop(class) }
                    .map(|(entry, lease)| (entry.buffer, lease, entry.slot))
            }
            None => class
                .global
                .take()
                .map(|(slot, buffer)| (buffer, SizeClassLease::retain(class), slot)),
        }
    }

    /// Returns the current thread's local cache for `class`.
    ///
    /// The raw fast path serves steady-state accesses and initializes missing
    /// size-class caches when the registry pointer is already available. The
    /// checked TLS path is only needed when this thread has not stored the raw
    /// registry pointer yet.
    #[inline(always)]
    fn cache(class: &SizeClassHandle) -> Option<ptr::NonNull<TlsSizeClassCache>> {
        let caches = Self::TLS_SIZE_CLASS_CACHES_FAST.with(|fast| fast.get());
        if !caches.is_null() {
            // SAFETY: the fast pointer is set only from this thread's
            // `TLS_SIZE_CLASS_CACHES` value and cleared before that value
            // drops.
            return Some(ptr::NonNull::from(unsafe {
                (&mut *caches).get_or_init(class)
            }));
        }

        Self::cache_slow(class)
    }

    /// Initializes the TLS fast path, then returns the local cache.
    ///
    /// This runs once per thread, when [`Self::cache`] finds no cached registry
    /// pointer. It goes through the checked owner TLS key, stores the registry
    /// pointer in [`Self::TLS_SIZE_CLASS_CACHES_FAST`], and then initializes the
    /// requested size-class cache if needed. We annotate with `inline(never)` to
    /// keep that one-time setup out of pooled allocation and drop.
    #[inline(never)]
    fn cache_slow(class: &SizeClassHandle) -> Option<ptr::NonNull<TlsSizeClassCache>> {
        // The owning TLS key has a destructor, so it can be unavailable during
        // thread-local teardown.
        Self::TLS_SIZE_CLASS_CACHES
            .try_with(|caches| {
                let caches = caches.get();
                Self::TLS_SIZE_CLASS_CACHES_FAST.with(|fast| fast.set(caches));

                // SAFETY: this TLS value is only ever accessed by the current thread.
                ptr::NonNull::from(unsafe { (&mut *caches).get_or_init(class) })
            })
            .ok()
    }
}

/// Internal allocation result for pooled allocations.
struct Allocation {
    buffer: PooledBuffer,
    is_new: bool,
    lease: SizeClassLease,
    slot: u32,
}

/// Internal state of the buffer pool.
pub(crate) struct BufferPoolInner {
    config: BufferPoolConfig,
    classes: Vec<SizeClassHandle>,
    metrics: PoolMetrics,
}

impl Drop for BufferPoolInner {
    fn drop(&mut self) {
        // The public pool is going away. Drain globally parked buffers while
        // the pool-owned class handles are still live. Pooled views and live
        // TLS cache entries own their own size-class references; if they return
        // later, they will park their buffer and release the reference that kept
        // the class alive.
        for class in &self.classes {
            class.global.drain();
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
    /// 3. **New allocation**: reserve a slot in the global freelist, then
    ///    allocate from the heap.
    ///
    /// If `zero_on_new` is true, newly-created buffers are allocated with
    /// `alloc_zeroed`. Reused buffers are never re-zeroed here.
    #[inline(always)]
    fn try_alloc(&self, class_index: usize, zero_on_new: bool) -> Option<Allocation> {
        let class = &self.classes[class_index];

        // Reuse path: try the thread-local cache first, then the global
        // freelist with batch refill when the local cache is large enough.
        if let Some((buffer, lease, slot)) = BufferPoolThreadCache::pop(class) {
            return Some(Allocation {
                buffer,
                is_new: false,
                lease,
                slot,
            });
        }

        // Slow path: create a new tracked buffer and update metrics.
        self.try_alloc_new(class, zero_on_new)
    }

    /// Creates a new tracked buffer after the reuse path fails.
    ///
    /// This is separate from [`Self::try_alloc`] so the steady-state allocation
    /// path can inline the TLS hit without also carrying slot reservation,
    /// metrics, and heap-allocation code.
    #[inline(never)]
    fn try_alloc_new(&self, class: &SizeClassHandle, zeroed: bool) -> Option<Allocation> {
        let label = SizeClassLabel {
            size_class: class.size as u64,
        };
        let Some((slot, buffer, lease)) = class.try_create(zeroed) else {
            self.metrics.exhausted_total.get_or_create(&label).inc();
            return None;
        };

        self.metrics.created.get_or_create(&label).inc();
        Some(Allocation {
            buffer,
            is_new: true,
            lease,
            slot,
        })
    }
}

/// A pool of reusable, aligned buffers.
///
/// Buffers are organized into power-of-two size classes. When a buffer is
/// requested, the smallest size class that fits is used. Pooled buffers are
/// automatically returned when their final owning view is dropped.
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

/// Global allocator for [`SizeClass::class_id`].
///
/// `class_id` is the key used by [`TlsSizeClassCaches`]. It must be global, not
/// pool-local, because the same thread-local registry serves every
/// [`BufferPool`] touched by the thread. Without a global id, two different
/// pools could share a class index and accidentally share one local cache.
///
/// Ids are monotonic and never reused. Reuse would make stale per-thread cache
/// state ambiguous after a pool is dropped and a later pool creates a new size
/// class with the same id. Avoiding reuse means the hot path can index directly
/// without generation checks, at the cost of possible holes in each thread's
/// sparse registry.
///
/// Relaxed ordering is sufficient: the atomic operation is only used to assign
/// unique ids, not to publish any associated size-class state.
static NEXT_SIZE_CLASS_ID: AtomicUsize = AtomicUsize::new(0);

impl BufferPool {
    /// Creates a new buffer pool with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if the configuration is invalid.
    pub(crate) fn new(config: BufferPoolConfig, registry: &mut impl Register) -> Self {
        config.validate();
        let metrics = PoolMetrics::new(registry);
        let num_classes =
            BufferPoolConfig::num_classes(config.min_size.get(), config.max_size.get());
        let mut classes = Vec::with_capacity(num_classes);
        let thread_cache_capacity = config.resolve_thread_cache_capacity();
        for i in 0..num_classes {
            let size = BufferPoolConfig::class_size(config.min_size.get(), i);
            let class_id = NEXT_SIZE_CLASS_ID.fetch_add(1, Ordering::Relaxed);
            let class = SizeClassHandle::new(
                class_id,
                size,
                config.alignment.get(),
                config.max_per_class,
                config.parallelism,
                thread_cache_capacity,
                config.prefill,
            );
            classes.push(class);
        }

        // Initialize created metrics after constructor prefill.
        if config.prefill {
            for class in &classes {
                let label = SizeClassLabel {
                    size_class: class.size as u64,
                };
                metrics
                    .created
                    .get_or_create(&label)
                    .set(config.max_per_class.get() as i64);
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

    /// Returns the size class index for a given size, or `None` if `size > max_size`.
    ///
    /// Pool construction validates the size-class bounds. This helper is in the
    /// allocation hot path, so it assumes those invariants and does not repeat
    /// validation.
    #[inline(always)]
    fn class_index(&self, size: usize) -> Option<usize> {
        let min_size = self.inner.config.min_size.get();
        let max_size = self.inner.config.max_size.get();
        if size > max_size {
            return None;
        }
        if size <= min_size {
            return Some(0);
        }

        // Pool construction guarantees `min_size` and `max_size` are powers of
        // two. Since `min_size < size <= max_size`, `next_power_of_two()`
        // resolves to a valid class and its exponent must be greater than
        // `min_size`'s exponent. Use wrapping arithmetic to avoid a release
        // overflow-check branch in this hot helper.
        Some(
            size.next_power_of_two()
                .trailing_zeros()
                .wrapping_sub(min_size.trailing_zeros()) as usize,
        )
    }

    /// Returns the size class index for `capacity`, recording oversized metrics on failure.
    #[inline]
    fn class_index_or_record_oversized(&self, capacity: usize) -> Option<usize> {
        let class_index = self.class_index(capacity);
        if class_index.is_none() {
            self.inner.metrics.oversized_total.inc();
        }
        class_index
    }

    /// Attempts to allocate a buffer without falling back on pool miss.
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
    /// - [`PoolError::Exhausted`]: pool exhausted for the required size class
    #[inline(always)]
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
            .map(|allocation| {
                PooledBufMut::new(allocation.buffer, allocation.lease, allocation.slot)
            })
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
    /// exhausted), this returns a pooled buffer that will be returned to the
    /// pool when dropped. Requests smaller than
    /// [`BufferPoolConfig::pool_min_size`] bypass pooling and return an
    /// untracked aligned allocation. Oversized or exhausted requests also fall
    /// back to an untracked aligned heap allocation that is deallocated when
    /// dropped.
    ///
    /// Use [`Self::try_alloc`] if eligible requests must fail instead of
    /// falling back to direct allocation.
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

    /// Attempts to allocate a zero-initialized buffer without falling back on
    /// pool miss.
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
    /// - [`PoolError::Exhausted`]: pool exhausted for the required size class
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

        let mut buf = IoBufMut::from_pooled(PooledBufMut::new(
            allocation.buffer,
            allocation.lease,
            allocation.slot,
        ));
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
    /// exhausted), this returns a pooled buffer that will be returned to the
    /// pool when dropped. Requests smaller than
    /// [`BufferPoolConfig::pool_min_size`] bypass pooling and return an
    /// untracked aligned allocation. Oversized or exhausted requests also fall
    /// back to an untracked aligned heap allocation that is deallocated when
    /// dropped.
    ///
    /// Use this for read APIs that require an initialized `&mut [u8]`.
    /// This avoids `unsafe set_len` at callsites.
    ///
    /// Use [`Self::try_alloc_zeroed`] if eligible requests must fail instead of
    /// falling back to direct allocation.
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
    use crate::{
        iobuf::{freelist, IoBuf},
        telemetry::metrics::Registry,
    };
    use bytes::{Buf, BufMut};
    use commonware_utils::NZU32;
    use std::{
        sync::{mpsc, Arc},
        thread,
    };

    fn test_size_class(size: usize, alignment: usize) -> SizeClassHandle {
        SizeClassHandle::new(
            NEXT_SIZE_CLASS_ID.fetch_add(1, Ordering::Relaxed),
            size,
            alignment,
            NZU32!(8),
            NZUsize!(4),
            4,
            false,
        )
    }

    fn test_pool(config: BufferPoolConfig) -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(config, &mut registry)
    }

    /// Creates a test config with page alignment.
    fn test_config(min_size: usize, max_size: usize, max_per_class: u32) -> BufferPoolConfig {
        BufferPoolConfig {
            pool_min_size: 0,
            min_size: NZUsize!(min_size),
            max_size: NZUsize!(max_size),
            max_per_class: NZU32!(max_per_class),
            parallelism: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::Enabled(None),
            prefill: false,
            alignment: NZUsize!(page_size()),
        }
    }

    /// Returns the current strong count without changing it after the helper
    /// returns.
    fn size_class_strong_count(class: &SizeClassHandle) -> usize {
        // SAFETY: the borrowed handle owns one strong reference for `class.token`
        // for the duration of this call.
        unsafe { class.token.retain() };
        // SAFETY: the increment above created the strong reference consumed by
        // this temporary Arc.
        let arc = unsafe { Arc::from_raw(class.token.ptr.as_ptr()) };
        Arc::strong_count(&arc) - 1
    }

    /// Helper to get the number of caller-owned tracked buffers for a size class.
    ///
    /// With TLS enabled, tracked buffers can be free in either the shared
    /// freelist or the current thread's local cache.
    fn get_allocated(pool: &BufferPool, size: usize) -> usize {
        let class_index = pool.class_index(size).unwrap();
        let class = &pool.inner.classes[class_index];
        get_global_created(class) - get_global_len(class) - get_local_len(class)
    }

    /// Helper to get the number of free buffers visible to the current thread.
    fn get_available(pool: &BufferPool, size: usize) -> i64 {
        let class_index = pool.class_index(size).unwrap();
        let class = &pool.inner.classes[class_index];
        (get_global_len(class) + get_local_len(class)) as i64
    }

    /// Helper to get the number of free buffers parked in the global freelist.
    fn get_global_len(class: &SizeClass) -> usize {
        freelist::tests::len(&class.global)
    }

    /// Helper to get the number of buffers created by the global freelist.
    fn get_global_created(class: &SizeClass) -> usize {
        freelist::tests::created(&class.global)
    }

    /// Helper to get the number of free buffers parked in the current thread's
    /// local cache for a size class.
    fn get_local_len(class: &SizeClass) -> usize {
        BufferPoolThreadCache::TLS_SIZE_CLASS_CACHES.with(|caches| {
            // SAFETY: this TLS value is only ever accessed by the current thread.
            let caches = unsafe { &*caches.get() };
            caches
                .bins
                .get(class.class_id)
                .and_then(Option::as_ref)
                .map_or(0, |cache| cache.len)
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
            max_per_class: NZU32!(10),
            parallelism: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::Enabled(None),
            prefill: false,
            alignment: NZUsize!(page_size()),
        };
        config.validate();
    }

    #[test]
    fn test_pool_class_index() {
        let page = page_size();
        let pool = test_pool(test_config(page, page * 8, 10));

        // Classes: page, page*2, page*4, page*8
        assert_eq!(pool.inner.classes.len(), 4);

        assert_eq!(pool.class_index(1), Some(0));
        assert_eq!(pool.class_index(page), Some(0));
        assert_eq!(pool.class_index(page + 1), Some(1));
        assert_eq!(pool.class_index(page * 2), Some(1));
        assert_eq!(pool.class_index(page * 4 + 1), Some(3));
        assert_eq!(pool.class_index(page * 8 - 1), Some(3));
        assert_eq!(pool.class_index(page * 8), Some(3));
        assert_eq!(pool.class_index(page * 8 + 1), None);
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
            max_per_class: NZU32!(2),
            parallelism: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::Enabled(None),
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
            max_per_class: NZU32!(5),
            parallelism: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::Enabled(None),
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
        assert_eq!(config.parallelism, NZUsize!(1));
        assert_eq!(
            config.thread_cache_config,
            BufferPoolThreadCacheConfig::Enabled(None)
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
        assert_eq!(config.parallelism, NZUsize!(1));
        assert_eq!(
            config.thread_cache_config,
            BufferPoolThreadCacheConfig::Enabled(None)
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
            .with_max_per_class(NZU32!(64))
            .with_parallelism(NZUsize!(4))
            .with_thread_cache_capacity(NZUsize!(8))
            .with_prefill(true)
            .with_min_size(page)
            .with_max_size(NZUsize!(128 * 1024));

        config.validate();
        assert_eq!(config.pool_min_size, 1024);
        assert_eq!(config.min_size, page);
        assert_eq!(config.max_size.get(), 128 * 1024);
        assert_eq!(config.max_per_class.get(), 64);
        assert_eq!(config.parallelism, NZUsize!(4));
        assert_eq!(
            config.thread_cache_config,
            BufferPoolThreadCacheConfig::Enabled(Some(NZUsize!(8)))
        );
        assert!(config.prefill);
        // Storage profile alignment stays page-sized unless explicitly changed.
        assert_eq!(config.alignment.get(), page_size());

        // Alignment can be tuned explicitly as long as min_size is also adjusted.
        let aligned = BufferPoolConfig::for_network()
            .with_pool_min_size(256)
            .with_parallelism(NZUsize!(4))
            .with_alignment(NZUsize!(256))
            .with_min_size(NZUsize!(256));
        aligned.validate();
        assert_eq!(aligned.parallelism, NZUsize!(4));
        assert_eq!(
            aligned.thread_cache_config,
            BufferPoolThreadCacheConfig::Enabled(None)
        );
        assert_eq!(aligned.alignment.get(), 256);
        assert_eq!(aligned.min_size.get(), 256);
    }

    #[test]
    fn test_parallelism_policy_resolves_thread_cache_capacity() {
        let page = page_size();

        // Half the class budget is divided across expected threads.
        let pool = test_pool(test_config(page, page, 64).with_parallelism(NZUsize!(8)));
        let class_index = pool.class_index(page).unwrap();
        assert_eq!(pool.inner.classes[class_index].thread_cache_capacity, 4);

        // Large classes scale past the previous eight-slot cap.
        let pool = test_pool(test_config(page, page, 4096).with_parallelism(NZUsize!(8)));
        let class_index = pool.class_index(page).unwrap();
        assert_eq!(pool.inner.classes[class_index].thread_cache_capacity, 256);
    }

    #[test]
    fn test_auto_thread_cache_disables_when_parallelism_exceeds_budget() {
        let page = page_size();

        // With only two buffers and eight expected threads, the auto policy's
        // per-thread share is zero: 2 / (2 * min(8, 2)) == 0. In that case the
        // pool should disable TLS instead of forcing every thread to retain at
        // least one buffer.
        let pool = test_pool(test_config(page, page, 2).with_parallelism(NZUsize!(8)));
        let class_index = pool.class_index(page).unwrap();
        let class = &pool.inner.classes[class_index];
        assert_eq!(class.thread_cache_capacity, 0);

        // Exhaust the size class so the only way the main thread can allocate
        // again is if the worker's returned buffers are globally visible.
        let first = pool.try_alloc(page).expect("first tracked allocation");
        let second = pool.try_alloc(page).expect("second tracked allocation");

        let pool_for_thread = pool.clone();
        let (returned_tx, returned_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            // Return both buffers from another thread. The thread stays alive
            // after the drops, so any TLS entries it retained would remain
            // invisible to the main thread until `release_rx` fires.
            drop(first);
            drop(second);
            returned_tx.send(()).expect("signal returned buffers");
            release_rx.recv().expect("release worker");
            drop(pool_for_thread);
        });

        returned_rx.recv().expect("wait for returned buffers");

        // Both allocations must succeed while the worker thread is still
        // alive. Before auto capacity could resolve to zero, one returned
        // buffer could remain stranded in the worker's TLS cache and this
        // second allocation would report exhaustion.
        let _first = pool.try_alloc(page).expect("first global reuse");
        let _second = pool.try_alloc(page).expect("second global reuse");

        release_tx.send(()).expect("release worker");
        handle.join().expect("worker should not panic");
    }

    #[test]
    fn test_parallelism_policy_resolves_freelist_stripes() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 64).with_parallelism(NZUsize!(16)));

        let class_index = pool.class_index(page).unwrap();
        assert_eq!(
            freelist::tests::num_words(&pool.inner.classes[class_index].global),
            16
        );

        // When expected parallelism rounds above capacity, the freelist caps
        // stripes so every word can contain at least one slot.
        let pool = test_pool(test_config(page, page, 12).with_parallelism(NZUsize!(9)));

        let class_index = pool.class_index(page).unwrap();
        assert_eq!(
            freelist::tests::num_words(&pool.inner.classes[class_index].global),
            8
        );

        // Disabling thread-local caches should not change global striping.
        let pool = test_pool(
            test_config(page, page, 64)
                .with_parallelism(NZUsize!(16))
                .with_thread_cache_disabled(),
        );

        let class_index = pool.class_index(page).unwrap();
        assert_eq!(
            freelist::tests::num_words(&pool.inner.classes[class_index].global),
            16
        );
    }

    #[test]
    fn test_fixed_thread_cache_capacity_overrides_auto_capacity() {
        let page = page_size();
        let pool = test_pool(
            test_config(page, page, 64)
                .with_parallelism(NZUsize!(8))
                .with_thread_cache_capacity(NZUsize!(7)),
        );
        let class_index = pool.class_index(page).unwrap();

        // Fixed capacity should bypass the derived parallelism heuristic.
        assert_eq!(pool.inner.classes[class_index].thread_cache_capacity, 7);
        assert_eq!(
            freelist::tests::num_words(&pool.inner.classes[class_index].global),
            8
        );
    }

    #[test]
    fn test_disabled_thread_cache_does_not_retain_buffers_locally() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2).with_thread_cache_disabled());
        let class_index = pool.class_index(page).unwrap();
        let class = &pool.inner.classes[class_index];

        let tracked = pool.try_alloc(page).expect("tracked allocation");
        drop(tracked);

        // Disabled thread caching still routes returns through the global
        // freelist, but should never retain buffers in the current thread.
        assert_eq!(class.thread_cache_capacity, 0);
        assert_eq!(get_local_len(class), 0);
        assert_eq!(get_global_len(class), 1);
    }

    #[test]
    fn test_thread_cache_flush_moves_local_entries_to_global() {
        let page = page_size();
        let pool =
            test_pool(test_config(page, page * 2, 8).with_thread_cache_capacity(NZUsize!(4)));

        // Use two distinct size classes so the test exercises the whole TLS
        // registry, not just a single per-class cache entry.
        let small_index = pool.class_index(page).unwrap();
        let large_index = pool.class_index(page + 1).unwrap();
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
        assert_eq!(get_global_len(small_class), 0);
        assert_eq!(get_global_len(large_class), 0);

        // Flushing should walk the entire TLS registry, drop every local cache,
        // and let each cache's drop implementation return its buffers to the
        // shared global freelists.
        BufferPoolThreadCache::flush();

        // After flush, the current thread retains nothing locally and both
        // buffers are once again visible through their class-global queues.
        assert_eq!(get_local_len(small_class), 0);
        assert_eq!(get_local_len(large_class), 0);
        assert_eq!(get_global_len(small_class), 1);
        assert_eq!(get_global_len(large_class), 1);
    }

    #[test]
    fn test_config_with_budget_bytes() {
        // Classes: 4, 8, 16 (sum = 28). Budget 280 => max_per_class = 10.
        let config = BufferPoolConfig {
            pool_min_size: 0,
            min_size: NZUsize!(4),
            max_size: NZUsize!(16),
            max_per_class: NZU32!(1),
            parallelism: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::Enabled(None),
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
            max_per_class: NZU32!(1),
            parallelism: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::Enabled(None),
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
            .class_index(page)
            .expect("class exists for page-sized buffer");

        let tracked1 = pool.try_alloc(page).expect("first tracked allocation");
        let tracked2 = pool.try_alloc(page).expect("second tracked allocation");

        // The first return should stay entirely in the current thread's local cache.
        drop(tracked1);
        assert_eq!(get_global_len(&pool.inner.classes[class_index]), 0);
        assert_eq!(get_local_len(&pool.inner.classes[class_index]), 1);

        // Returning another tracked buffer should route overflow to the global
        // freelist and retain one in the current thread's local bin.
        drop(tracked2);
        assert_eq!(get_global_len(&pool.inner.classes[class_index]), 1);
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
        let max_per_class =
            u32::try_from(threads * 8).expect("test capacity must fit in u32 slot ids");
        let pool = test_pool(test_config(page, page, max_per_class));
        let class_index = pool
            .class_index(page)
            .expect("class exists for page-sized buffer");
        let class = &pool.inner.classes[class_index];

        assert!(class.thread_cache_capacity >= MIN_TLS_BATCH_CAPACITY);

        // Drop enough distinct pooled buffers to force an overflow from a
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
        assert_eq!(get_global_len(class), class.thread_cache_capacity / 2);

        // Drain the local half, then hit global once. That global take should
        // batch-refill the local cache back up to the configured target.
        let mut reused = Vec::new();
        for _ in 0..class.thread_cache_capacity / 2 + 1 {
            reused.push(pool.try_alloc(page).expect("local reuse"));
        }
        assert_eq!(get_local_len(class), 0);
        assert_eq!(get_global_len(class), class.thread_cache_capacity / 2);

        let _global = pool.try_alloc(page).expect("global reuse with refill");
        assert_eq!(get_local_len(class), class.thread_cache_capacity / 2 - 1);
        assert_eq!(get_global_len(class), 0);
    }

    #[test]
    fn test_global_batch_alloc_stops_when_global_runs_empty() {
        let class = test_size_class(64, 64);
        let (slot, buffer) = class.global.try_create(false).expect("slot reservation");

        // A short global freelist should return the allocation and stop
        // without filling the local cache to its batch target.
        class.global.put(slot, buffer);
        let (buffer, lease, slot) = BufferPoolThreadCache::pop(&class).expect("global allocation");

        assert_eq!(get_local_len(&class), 0);
        assert_eq!(get_global_len(&class), 0);

        // Return the manually popped entry so the freelist owns and deallocates
        // the buffer at test teardown.
        lease.return_global(slot, buffer);
    }

    #[test]
    fn test_size_class_leases_use_raw_arc_tokens_across_cache_paths() {
        let class = test_size_class(64, 64);
        let mut cache = TlsSizeClassCache::new(&class, MIN_TLS_BATCH_CAPACITY);
        assert_eq!(size_class_strong_count(&class), 1);

        let (slot, buffer) = class.global.try_create(false).expect("slot reservation");
        let lease = SizeClassLease::retain(&class);
        assert_eq!(size_class_strong_count(&class), 2);

        // Moving a pooled-buffer lease into the local cache banks the same strong
        // reference; it should not clone the class.
        cache.push(lease, slot, buffer);
        assert_eq!(size_class_strong_count(&class), 2);

        let (entry, lease) = cache.pop(&class).expect("local cache pop");
        assert_eq!(size_class_strong_count(&class), 2);
        lease.return_global(entry.slot, entry.buffer);
        assert_eq!(size_class_strong_count(&class), 1);

        for _ in 0..2 {
            let (slot, buffer) = class.global.try_create(false).expect("slot reservation");
            class.global.put(slot, buffer);
        }

        let (entry, lease) = cache.pop(&class).expect("global refill");
        assert_eq!(size_class_strong_count(&class), 3);

        lease.return_global(entry.slot, entry.buffer);
        assert_eq!(size_class_strong_count(&class), 2);

        // Dropping the cache returns the banked refill entry and releases its
        // size-class reference.
        drop(cache);
        assert_eq!(size_class_strong_count(&class), 1);
    }

    #[test]
    fn test_tls_size_class_cache_push_tolerates_empty_spill() {
        let class = test_size_class(64, 64);
        let (slot, buffer) = class.global.try_create(false).expect("slot reservation");
        let lease = SizeClassLease::retain(&class);
        let mut cache = TlsSizeClassCache::new(&class, 0);

        // Small local capacities should bypass batching and push straight to
        // global. The retained reference above is represented by this lease and
        // transferred into `cache.push`.
        cache.push(lease, slot, buffer);
        assert_eq!(cache.len, 0);
        drop(cache);
    }

    #[test]
    fn test_global_freelist_returns_each_slot_once() {
        // Use a two-slot class with TLS capacity one so this test can exercise
        // the class-global freelist directly without involving local-cache
        // refill or spill behavior.
        let class = SizeClassHandle::new(
            NEXT_SIZE_CLASS_ID.fetch_add(1, Ordering::Relaxed),
            64,
            64,
            NZU32!(2),
            NZUsize!(1),
            1,
            false,
        );

        // Create both slot ids and keep each allocation's pointer so we can
        // verify that the freelist returns the same buffer parked for that slot.
        let (slot0, buffer0) = class.global.try_create(false).expect("first slot");
        let ptr0 = buffer0.as_ptr();
        let (slot1, buffer1) = class.global.try_create(false).expect("second slot");
        let ptr1 = buffer1.as_ptr();

        class.global.put(slot0, buffer0);
        class.global.put(slot1, buffer1);

        // The freelist does not preserve insertion order, so normalize by slot
        // before asserting identity. The important property is that each slot is
        // returned exactly once with its original parked buffer.
        let mut popped = [
            class.global.take().expect("first pop"),
            class.global.take().expect("second pop"),
        ];
        popped.sort_by_key(|(slot, _)| *slot);

        assert_eq!(popped[0].0, slot0);
        assert_eq!(popped[0].1.as_ptr(), ptr0);
        assert_eq!(popped[1].0, slot1);
        assert_eq!(popped[1].1.as_ptr(), ptr1);

        // Both slots were claimed above, so the global freelist is empty.
        assert!(class.global.take().is_none());

        // Return the buffers so the freelist owns and deallocates them when the
        // test size class is dropped.
        for (slot, buffer) in popped {
            class.global.put(slot, buffer);
        }
    }

    #[test]
    fn test_pooled_debug_and_empty_into_bytes_paths() {
        // Debug formatting for pooled mutable/immutable wrappers, and empty
        // into_bytes should detach without retaining the pool allocation.
        let page = page_size();
        let class = test_size_class(page, page);
        let (slot0, buffer0, class0) = class.try_create(false).expect("first slot");
        let (slot1, buffer1, class1) = class.try_create(false).expect("second slot");
        let (slot2, buffer2, class2) = class.try_create(false).expect("third slot");

        // Mutable pooled debug should include cursor position.
        let pooled_mut_debug = {
            let pooled_mut = PooledBufMut::new(buffer0, class0, slot0);
            format!("{pooled_mut:?}")
        };
        assert!(pooled_mut_debug.contains("PooledBufMut"));
        assert!(pooled_mut_debug.contains("cursor"));

        // Empty mutable buffer converts to empty Bytes without retaining pool memory.
        let empty_from_mut = PooledBufMut::new(buffer1, class1, slot1);
        assert!(empty_from_mut.into_bytes().is_empty());

        // Immutable pooled debug should include capacity.
        let pooled = PooledBufMut::new(buffer2, class2, slot2).into_pooled();
        let pooled_debug = format!("{pooled:?}");
        assert!(pooled_debug.contains("PooledBuf"));
        assert!(pooled_debug.contains("capacity"));
        assert!(pooled.into_bytes().is_empty());

        BufferPoolThreadCache::flush();
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

        // Receive and drop on another thread. Since that thread has not
        // initialized a local cache for this class, those returns should go to
        // the global freelist instead of creating TLS state from a drop path.
        let handle = thread::spawn(move || {
            while let Ok(iobuf) = rx.recv() {
                drop(iobuf);
            }

            let class_index = pool
                .class_index(page)
                .expect("class exists for page-sized buffer");
            assert_eq!(get_local_len(&pool.inner.classes[class_index]), 0);
            assert_eq!(get_global_len(&pool.inner.classes[class_index]), 50);

            for _ in 0..50 {
                let _buf = pool
                    .try_alloc(page)
                    .expect("dropping thread should be able to reuse globally returned buffers");
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
            .class_index(page)
            .expect("class exists for page-sized buffer");
        assert_eq!(get_global_len(&pool.inner.classes[class_index]), 1);
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
            .class_index(page)
            .expect("class exists for page-sized buffer");
        let class = &pool.inner.classes[class_index];
        // Keep a test-owned handle so the class remains inspectable after
        // dropping the public pool below.
        // SAFETY: `class` owns one strong reference for `class.token`.
        unsafe { class.token.retain() };
        let class = SizeClassHandle { token: class.token };

        // Return one buffer to the current thread's local cache and overflow
        // the other into the shared global freelist.
        let buf1 = pool.try_alloc(page).unwrap();
        let buf2 = pool.try_alloc(page).unwrap();
        drop(buf1);
        drop(buf2);

        assert_eq!(get_global_len(&class), 1);
        assert_eq!(get_local_len(&class), 1);

        // Pool drop should drain only the global freelist. The thread-local
        // cache remains untouched until thread exit.
        drop(pool);

        assert_eq!(get_global_len(&class), 0);
        assert_eq!(get_local_len(&class), 1);
        assert_eq!(get_global_created(&class), 2);
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
                    max_per_class: NZU32!(32),
                    ..BufferPoolConfig::for_storage()
                };
                let network_config = BufferPoolConfig {
                    max_per_class: NZU32!(32),
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
