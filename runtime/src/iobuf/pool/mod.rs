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
//! Allocation and deallocation use atomic counters together with a global
//! freelist split across mutex-protected stripes, each with a fixed slot limit,
//! plus per-thread caches.
//!
//! Global freelist operations use blocking mutexes. After a local cache miss or
//! spill, an operation can wait for a stripe lock. A preempted lock holder can
//! therefore delay the operation even when another stripe could provide or
//! accept a buffer.
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
//! - Dropping [`BufferPool`] drains only the shared global freelists. Pooled
//!   views and buffers cached in a live thread's local cache can keep their
//!   size class alive until they are dropped or the thread exits.
//!
//! # Size Classes
//!
//! Buffers are organized into power-of-two size classes. The enabled classes
//! do not need to be contiguous, and each class has its own tracked-buffer
//! limit. For example, with enabled classes 4096, 8192, and 32768:
//! - Class 0: 4096 bytes
//! - Class 1: 8192 bytes
//! - Class 2: 32768 bytes
//!
//! Allocation requests round up to the smallest enabled class that fits, so a
//! 16000-byte request above is served by the 32768-byte class. Requests larger
//! than the largest enabled class return [`PoolError::Oversized`] from
//! [`BufferPool::try_alloc`], or fall back to an untracked aligned heap
//! allocation from [`BufferPool::alloc`]. A request routed to an exhausted
//! class returns [`PoolError::Exhausted`] without trying larger classes.
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

mod class;
mod freelist;

use super::{IoBufMut, page_size};
use crate::{
    iobuf::owner::PooledBuffer,
    telemetry::metrics::{Counter, CounterFamily, EncodeLabelSet, GaugeFamily, Register, raw},
};
pub use class::BufferPoolThreadCache;
use class::SizeClassHandle;
pub(crate) use class::SizeClassLease;
use commonware_utils::{NZU32, NZUsize};
pub(super) use freelist::Freelist;
use std::{
    collections::BTreeMap,
    num::{NonZeroU32, NonZeroUsize},
    sync::atomic::{AtomicUsize, Ordering},
};
use thiserror::Error;

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

/// Error returned when buffer pool allocation fails.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolError {
    /// The requested capacity exceeds the maximum buffer size.
    #[error("requested capacity exceeds maximum buffer size")]
    Oversized,
    /// The pool is exhausted for the required size class.
    #[error("pool exhausted for required size class")]
    Exhausted,
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
    /// `Some(n)` uses an explicit per-thread cache size, clamped independently
    /// to each size class's limit.
    Enabled(Option<NonZeroUsize>),
    /// Disable thread-local caching and route all reuse through the shared global freelist.
    Disabled,
}

/// Configuration for one enabled buffer pool size class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferPoolClassConfig {
    /// Buffer size for this class. Must be a power of two.
    pub size: NonZeroUsize,
    /// Maximum number of tracked buffers in this class.
    ///
    /// Size-class slots are identified by `u32`, so the per-class limit is
    /// capped by this type.
    pub max_buffers: NonZeroU32,
}

impl From<(NonZeroUsize, NonZeroU32)> for BufferPoolClassConfig {
    fn from((size, max_buffers): (NonZeroUsize, NonZeroU32)) -> Self {
        Self { size, max_buffers }
    }
}

/// Configuration for a buffer pool.
///
/// The class layout is a set of power-of-two size classes, each with its own
/// tracked-buffer limit. Enabled classes do not need to be contiguous, and
/// requests route to the smallest enabled class that fits.
///
/// Shape builders do not commute. Each builder applies to the layout produced
/// by the previous one: replacement builders ([`Self::with_size_class_range`],
/// [`Self::with_size_classes`]) discard the current layout, uniform builders
/// ([`Self::with_max_per_class`], [`Self::with_bytes_per_class`]) overwrite
/// every enabled limit, and [`Self::with_budget_bytes`] snapshots and rescales
/// the shape that exists at that call.
#[derive(Clone, Debug)]
pub struct BufferPoolConfig {
    /// Minimum request size that should use pooled allocation.
    ///
    /// Requests smaller than this bypass the pool and use direct aligned
    /// allocation instead. A value of `0` means all eligible requests use the
    /// pool.
    pool_min_size: usize,
    /// Enabled size classes, keyed by power-of-two size. Sizes absent from the
    /// map are disabled.
    ///
    /// Builders maintain the invariant that at least one class is enabled.
    class_limits: BTreeMap<NonZeroUsize, NonZeroU32>,
    /// Whether to create every tracked buffer during pool construction.
    ///
    /// When enabled, each size class creates its configured limit of buffers
    /// and parks them in the class-global freelist before the pool is
    /// returned. This moves allocation cost to startup and makes the first
    /// reuse path avoid heap allocation.
    prefill: bool,
    /// Buffer alignment. Must be a power of two.
    alignment: NonZeroUsize,
    /// Expected number of threads concurrently accessing the pool.
    ///
    /// This sizes the shared global freelist stripes. It is also used to derive
    /// thread-cache capacity when the thread-cache policy is automatic, using
    /// approximately half of each class limit divided across expected threads.
    parallelism: NonZeroUsize,
    /// Policy for sizing the per-thread local cache in each size class.
    ///
    /// By default, thread-cache capacity is derived from [`Self::parallelism`]
    /// and each class limit. [`Self::with_max_thread_cache_capacity`] uses an
    /// explicit per-thread cache size clamped to each class limit.
    /// [`Self::with_thread_cache_disabled`] bypasses thread-local caches.
    pub(crate) thread_cache_config: BufferPoolThreadCacheConfig,
}

impl BufferPoolConfig {
    /// Network I/O preset: 1KB to 128KB buffers, 4096 per class, not prefilled.
    ///
    /// Network operations typically need multiple concurrent buffers per
    /// connection (message, encoding, encryption) so we allow 4096 buffers per
    /// size class.
    pub fn for_network() -> Self {
        Self {
            pool_min_size: 0,
            class_limits: BTreeMap::new(),
            prefill: false,
            alignment: NZUsize!(1),
            parallelism: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::Enabled(None),
        }
        .with_size_class_range(NZUsize!(1024), NZUsize!(128 * 1024), NZU32!(4096))
    }

    /// Storage I/O preset: `page_size` (usually 4KB) to 8MB buffers, 64 per class,
    /// not prefilled.
    pub fn for_storage() -> Self {
        Self {
            pool_min_size: 0,
            class_limits: BTreeMap::new(),
            prefill: false,
            // TODO (#2960): this needs to be page/block aligned for O_DIRECT
            alignment: NZUsize!(1),
            parallelism: NZUsize!(1),
            thread_cache_config: BufferPoolThreadCacheConfig::Enabled(None),
        }
        .with_size_class_range(
            NZUsize!(page_size()),
            NZUsize!(8 * 1024 * 1024),
            NZU32!(64),
        )
    }

    /// Validates a class size, panicking on invalid values.
    ///
    /// Sizes above `isize::MAX` are rejected here because `Layout` cannot
    /// represent them, which would otherwise surface as a misleading panic at
    /// pool construction.
    const fn validate_class_size(size: NonZeroUsize) {
        assert!(
            size.get().is_power_of_two(),
            "class size must be a power of two"
        );
        assert!(
            size.get() <= isize::MAX as usize,
            "class size must not exceed isize::MAX"
        );
    }

    /// Returns a copy of this config with a new minimum request size that uses pooling.
    pub const fn with_pool_min_size(mut self, pool_min_size: usize) -> Self {
        self.pool_min_size = pool_min_size;
        self
    }

    /// Returns a copy of this config whose layout is the inclusive, contiguous
    /// power-of-two range from `min` to `max` with a uniform limit.
    ///
    /// This replaces the complete class layout.
    ///
    /// # Panics
    ///
    /// - `min` or `max` is not a power of two
    /// - `min` or `max` exceeds `isize::MAX`
    /// - `max < min`
    pub fn with_size_class_range(
        self,
        min: NonZeroUsize,
        max: NonZeroUsize,
        max_buffers: NonZeroU32,
    ) -> Self {
        Self::validate_class_size(min);
        Self::validate_class_size(max);
        assert!(max >= min, "max size must be >= min size");

        self.with_size_classes(
            (min.get().trailing_zeros()..=max.get().trailing_zeros())
                .map(|exponent| (NZUsize!(1 << exponent), max_buffers)),
        )
    }

    /// Returns a copy of this config whose layout is exactly the given classes.
    ///
    /// This replaces the complete class layout. Input order does not matter,
    /// classes are normalized into ascending size order.
    ///
    /// # Panics
    ///
    /// - `classes` is empty
    /// - a class size is not a power of two
    /// - a class size exceeds `isize::MAX`
    /// - two classes have the same size
    pub fn with_size_classes<I, C>(mut self, classes: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<BufferPoolClassConfig>,
    {
        let mut limits = BTreeMap::new();
        for class in classes {
            let class = class.into();
            Self::validate_class_size(class.size);
            assert!(
                limits.insert(class.size, class.max_buffers).is_none(),
                "duplicate class size {}",
                class.size
            );
        }
        assert!(
            !limits.is_empty(),
            "class layout must enable at least one class"
        );
        self.class_limits = limits;
        self
    }

    /// Returns a copy of this config with the given class enabled, replacing
    /// its limit if it is already enabled.
    ///
    /// # Panics
    ///
    /// - `size` is not a power of two
    /// - `size` exceeds `isize::MAX`
    pub fn with_size_class(mut self, size: NonZeroUsize, max_buffers: NonZeroU32) -> Self {
        Self::validate_class_size(size);
        self.class_limits.insert(size, max_buffers);
        self
    }

    /// Returns a copy of this config with the given class removed.
    ///
    /// Requests that previously routed to the removed class route to the next
    /// larger enabled class.
    ///
    /// # Panics
    ///
    /// - `size` is not a power of two
    /// - `size` exceeds `isize::MAX`
    /// - no class with `size` is enabled
    /// - the class is the final enabled class
    pub fn without_size_class(mut self, size: NonZeroUsize) -> Self {
        Self::validate_class_size(size);
        assert!(
            self.class_limits.remove(&size).is_some(),
            "cannot remove a class that is not enabled"
        );
        assert!(
            !self.class_limits.is_empty(),
            "cannot remove the final enabled class"
        );
        self
    }

    /// Returns a copy of this config with the same limit on every enabled class.
    pub fn with_max_per_class(mut self, max_buffers: NonZeroU32) -> Self {
        for limit in self.class_limits.values_mut() {
            *limit = max_buffers;
        }
        self
    }

    /// Returns a copy of this config where every enabled class has
    /// approximately the same tracked-byte weight.
    ///
    /// Each enabled class's limit becomes `max(1, bytes / size)`, so limits
    /// halve as class sizes double. This is a one-shot count transformation,
    /// not a stored byte policy, and it never disables a class.
    ///
    /// # Panics
    ///
    /// Panics if a derived limit exceeds `u32::MAX`.
    pub fn with_bytes_per_class(mut self, bytes: NonZeroUsize) -> Self {
        for (size, limit) in self.class_limits.iter_mut() {
            let count = bytes.get() / size.get();
            assert!(
                count <= u32::MAX as usize,
                "per-class byte weight derives a limit above u32::MAX"
            );
            *limit = NonZeroU32::new(count.max(1) as u32).expect("count is at least one");
        }
        self
    }

    /// Returns a copy of this config with a new expected parallelism.
    ///
    /// The global freelist derives its stripe count from this target and the
    /// class capacity. This value also controls thread-cache capacity when the
    /// thread-cache policy is automatic. The automatic policy reserves about
    /// half of each class for the global freelist and divides the remaining
    /// capacity across expected threads.
    pub const fn with_parallelism(mut self, parallelism: NonZeroUsize) -> Self {
        self.parallelism = parallelism;
        self
    }

    /// Returns a copy of this config with an explicit per-thread cache size.
    ///
    /// Each size class keeps a small per-thread cache of free buffers for
    /// same-thread reuse. By default its capacity is derived per class from
    /// the class limit and [`Self::parallelism`], reserving about half of the
    /// class for the shared global freelist. An explicit capacity replaces
    /// that derivation and may be larger or smaller than the derived value.
    ///
    /// The effective capacity for each class is `min(capacity, class limit)`.
    /// Clamping happens independently per class, so one small class cannot
    /// invalidate the configuration.
    ///
    /// Buffers held in a thread's cache are invisible to other threads until
    /// they spill to the global freelist or the thread exits, and each thread
    /// can retain up to the effective capacity of every class it touches.
    /// Larger values favor same-thread reuse while smaller values favor
    /// cross-thread visibility and a lower per-thread memory ceiling.
    ///
    /// Global-freelist striping is set separately by [`Self::with_parallelism`].
    pub const fn with_max_thread_cache_capacity(mut self, capacity: NonZeroUsize) -> Self {
        self.thread_cache_config = BufferPoolThreadCacheConfig::Enabled(Some(capacity));
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

    /// Returns a copy of this config with all class limits proportionally
    /// rescaled under a strict tracked-byte ceiling.
    ///
    /// This snapshots the currently enabled classes and their limits, then
    /// chooses the greatest common proportional scale for which the total
    /// tracked capacity `sum(size * scaled_limit)` stays within `budget`,
    /// where `scaled_limit = max(1, floor(limit * scale))`. Scaling may raise
    /// or lower limits, never disables a class, and may deliberately leave
    /// part of the budget unused rather than distort the requested shape.
    ///
    /// The budget covers tracked buffer payload capacity only. It does not
    /// include allocator metadata, alignment overhead, or pool bookkeeping.
    ///
    /// This is a one-shot transformation, not a stored policy. Later builder
    /// calls may change the resulting total, and calling this again rescales
    /// the already scaled limits rather than the shape they were derived from.
    ///
    /// # Panics
    ///
    /// - `budget` is smaller than one buffer from every enabled class
    /// - the budget would require scaling a limit above `u32::MAX`
    pub fn with_budget_bytes(mut self, budget: NonZeroUsize) -> Self {
        let budget = budget.get() as u128;

        // The smallest expressible footprint keeps one buffer per class.
        let minimum: u128 = self
            .class_limits
            .keys()
            .map(|size| size.get() as u128)
            .sum();
        assert!(
            budget >= minimum,
            "budget must cover at least one buffer from every enabled class"
        );

        // Scales are unsigned Q64.64 fixed-point. Since class limits fit in
        // u32, consecutive distinct count-change breakpoints k1/c1 and k2/c2
        // are separated by at least 1/(c1*c2) > 2^-64, i.e. more than one
        // fixed-point step, so the maximal feasible count plateau always
        // contains a representable scale and the binary search below finds an
        // optimal count vector.
        const FRACTION_BITS: u32 = 64;

        // Scaled limit for one class. The u32 slot-identifier bound is
        // enforced by `evaluate` and the post-search assert below. Saturating
        // math keeps the evaluation monotonic for scales beyond that bound
        // instead of overflowing.
        let scaled = |limit: NonZeroU32, scale: u128| -> u128 {
            ((limit.get() as u128).saturating_mul(scale) >> FRACTION_BITS).max(1)
        };
        // Saturating total tracked bytes at a scale, and whether every scaled
        // limit still fits u32 slot identifiers. Both constraints are
        // monotonically violated as the scale grows, so feasibility is a
        // prefix of the scale axis and binary search applies.
        let evaluate = |scale: u128| -> (u128, bool) {
            self.class_limits
                .iter()
                .fold((0u128, true), |(total, fits), (&size, &limit)| {
                    let count = scaled(limit, scale);
                    (
                        total.saturating_add(count.saturating_mul(size.get() as u128)),
                        fits && count <= u32::MAX as u128,
                    )
                })
        };
        let feasible = |scale: u128| -> bool {
            let (total, fits) = evaluate(scale);
            total <= budget && fits
        };

        // Scale zero floors every class at one buffer, which the minimum
        // check above proved feasible. The upper bound exceeds any scale that
        // could keep the smallest possible limit within u32, so it is
        // infeasible and the search invariant holds at both ends.
        let mut lo: u128 = 0;
        let mut hi: u128 = (u32::MAX as u128 + 1) << FRACTION_BITS;
        assert!(feasible(lo), "scale zero must be feasible");
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if feasible(mid) {
                lo = mid;
            } else {
                hi = mid;
            }
        }

        // The next representable scale is infeasible. If its total would
        // still fit the budget, the binding constraint is the u32 limit
        // bound, which the caller must resolve instead of silently capping.
        let (next_total, _) = evaluate(lo + 1);
        assert!(
            next_total > budget,
            "budget requires scaling a class limit above u32::MAX"
        );

        // Rescale each limit in place at the optimal feasible scale.
        for limit in self.class_limits.values_mut() {
            let count = u32::try_from(scaled(*limit, lo)).expect("feasible count fits u32");
            *limit = NonZeroU32::new(count).expect("count is at least one");
        }
        self
    }

    /// Returns an iterator over enabled classes in ascending size order.
    pub fn size_classes(&self) -> impl ExactSizeIterator<Item = BufferPoolClassConfig> + '_ {
        self.class_limits
            .iter()
            .map(|(&size, &max_buffers)| BufferPoolClassConfig { size, max_buffers })
    }

    /// Returns the enabled class that serves a pooled request of `size` bytes,
    /// or `None` if `size` exceeds the largest enabled class.
    ///
    /// Requests route to the smallest enabled class that fits, so in sparse
    /// layouts the returned class may be much larger than the request. This
    /// reports class shape only: zero-sized requests and requests below
    /// [`Self::pool_min_size`] bypass the pool, and oversized requests fall
    /// back to untracked aligned allocations with capacity at least as large
    /// as the request.
    pub fn class_for(&self, size: usize) -> Option<BufferPoolClassConfig> {
        self.size_classes().find(|class| class.size.get() >= size)
    }

    /// Returns the minimum request size that uses pooled allocation.
    pub const fn pool_min_size(&self) -> usize {
        self.pool_min_size
    }

    /// Returns whether every tracked buffer is created during pool construction.
    pub const fn prefill(&self) -> bool {
        self.prefill
    }

    /// Returns the buffer alignment.
    pub const fn alignment(&self) -> NonZeroUsize {
        self.alignment
    }

    /// Returns the expected number of threads concurrently accessing the pool.
    pub const fn parallelism(&self) -> NonZeroUsize {
        self.parallelism
    }

    /// Returns the smallest enabled class size.
    pub fn min_size(&self) -> NonZeroUsize {
        *self
            .class_limits
            .first_key_value()
            .expect("class layout must enable at least one class")
            .0
    }

    /// Returns the largest enabled class size.
    pub fn max_size(&self) -> NonZeroUsize {
        *self
            .class_limits
            .last_key_value()
            .expect("class layout must enable at least one class")
            .0
    }

    /// Returns `sum(class size * class limit)`, saturating at `usize::MAX`.
    ///
    /// A saturated result means the configured maximum tracked capacity is at
    /// least that large.
    pub fn max_tracked_bytes(&self) -> usize {
        self.class_limits
            .iter()
            .map(|(size, limit)| size.get().saturating_mul(limit.get() as usize))
            .fold(0usize, usize::saturating_add)
    }

    /// Validates cross-field constraints, panicking on invalid values.
    ///
    /// Layout-local mistakes panic at the builder call that introduces them.
    /// The constraints here span independently configured fields, so they are
    /// deferred to pool construction to keep builder order unrestricted.
    ///
    /// # Panics
    ///
    /// - `alignment` is not a power of two
    /// - the smallest enabled class is smaller than `alignment`
    /// - `pool_min_size` is larger than the smallest enabled class
    fn validate(&self) {
        assert!(
            self.alignment.is_power_of_two(),
            "alignment must be a power of two"
        );
        let min_size = self.min_size();
        assert!(
            min_size >= self.alignment,
            "smallest class ({}) must be >= alignment ({})",
            min_size,
            self.alignment
        );
        assert!(
            self.pool_min_size <= min_size.get(),
            "pool_min_size ({}) must be <= smallest class ({})",
            self.pool_min_size,
            min_size
        );
    }

    /// Resolves the effective per-thread cache size for one size class.
    ///
    /// Derived capacities divide half of the class limit across the expected
    /// parallelism so cross-thread reuse remains effective. Small class limits
    /// may resolve to zero. An explicit capacity replaces the derivation and
    /// clamps to the class limit.
    fn resolve_thread_cache_capacity(&self, class_limit: NonZeroU32) -> usize {
        let class_limit = class_limit.get() as usize;
        match self.thread_cache_config {
            BufferPoolThreadCacheConfig::Enabled(None) => {
                let effective_threads = self.parallelism.get().min(class_limit);
                class_limit / effective_threads.saturating_mul(2)
            }
            BufferPoolThreadCacheConfig::Enabled(Some(capacity)) => capacity.get().min(class_limit),
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
            // Counters are registered without the `_total` suffix because the
            // prometheus encoder appends it to counter names.
            exhausted_total: registry.register(
                "buffer_pool_exhausted",
                "Total number of failed allocations due to pool exhaustion",
                raw::Family::default(),
            ),
            oversized_total: registry.register(
                "buffer_pool_oversized",
                "Total number of allocation requests exceeding max buffer size",
                raw::Counter::default(),
            ),
        }
    }
}

/// Internal allocation result for pooled allocations.
struct Allocation {
    buffer: PooledBuffer,
    is_new: bool,
}

/// Internal state of the buffer pool.
pub(crate) struct BufferPoolInner {
    config: BufferPoolConfig,
    /// Exponent-indexed routing vector.
    ///
    /// Entry `i` serves requests that round up to `min_size << i`. Disabled
    /// exponents hold cloned handles that alias the next enabled class, so
    /// the allocation path resolves any request with plain arithmetic and one
    /// vector index. Aliased entries form contiguous runs that end at the
    /// enabled class's own exponent.
    classes: Vec<SizeClassHandle>,
    /// Smallest enabled class size, cached off [`BufferPoolConfig`] so the
    /// allocation path never scans the configuration table.
    min_size: usize,
    /// Largest enabled class size, cached for the same reason.
    max_size: usize,
    metrics: PoolMetrics,
}

impl Drop for BufferPoolInner {
    fn drop(&mut self) {
        // The public pool is going away. Drain globally parked buffers while
        // the pool-owned class handles are still live. Pooled views and live
        // TLS cache entries own their own size-class references. If they
        // return later, they park their buffer and release the reference that
        // kept the class alive.
        //
        // Routing entries alias the next enabled class in contiguous runs, so
        // dropping consecutive duplicates leaves one live handle per unique
        // class and drains each class once.
        self.classes.dedup_by(|a, b| a.same_class(b));
        assert_eq!(self.classes.len(), self.config.size_classes().len());
        for class in &self.classes {
            class.drain_global();
        }
    }
}

impl BufferPoolInner {
    /// Try to allocate a buffer from the given size class.
    ///
    /// Uses a three-tier strategy:
    /// 1. **Thread-local cache** (fast path): no atomics, no contention.
    /// 2. **Global freelist**: striped pop, then batch-refill the local cache
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
        if let Some(buffer) = BufferPoolThreadCache::pop(class) {
            return Some(Allocation {
                buffer,
                is_new: false,
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
            size_class: class.size() as u64,
        };
        let Some(buffer) = class.try_create(zeroed) else {
            self.metrics.exhausted_total.get_or_create(&label).inc();
            return None;
        };

        self.metrics.created.get_or_create(&label).inc();
        Some(Allocation {
            buffer,
            is_new: true,
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
/// Buffer alignment is guaranteed only at the allocation base, where a
/// freshly allocated buffer's pointer starts. After [`bytes::Buf::advance`],
/// the pointer returned by `as_mut_ptr()` may no longer be aligned. For
/// direct I/O operations that require alignment, do not advance the buffer
/// before use.
///
/// # Thread-local caching
///
/// Returned buffers are cached per thread for reuse. After the pool is
/// dropped, buffers still cached on other threads are reclaimed when those
/// threads exit or call [`BufferPoolThreadCache::flush`]. A long-lived
/// thread that used a since-dropped pool retains its cached buffers until
/// then. Processes that create and drop many pools should reuse threads'
/// pools or flush explicitly.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<BufferPoolInner>,
}

impl std::fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferPool")
            .field("config", &self.inner.config)
            .field("num_classes", &self.inner.config.size_classes().len())
            .finish()
    }
}

/// Global allocator for size-class TLS registry ids.
///
/// `class_id` is the key used by each thread's cache registry. It must be global, not
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
        let min_size = config.min_size().get();
        let max_size = config.max_size().get();
        let min_exponent = min_size.trailing_zeros() as usize;
        let max_exponent = max_size.trailing_zeros() as usize;

        // Create one allocator per enabled class and expand the exponent-indexed
        // routing vector up to it. Every exponent in the enabled span resolves
        // to the smallest enabled class at or above it, so the gap entries
        // `resize` fills below each class alias that class. Prefill happens
        // inside `SizeClassHandle::new`, once per unique class.
        let mut classes = Vec::with_capacity(max_exponent - min_exponent + 1);
        for class_config in config.size_classes() {
            let class_id = NEXT_SIZE_CLASS_ID.fetch_add(1, Ordering::Relaxed);
            let handle = SizeClassHandle::new(
                class_id,
                class_config.size.get(),
                config.alignment.get(),
                class_config.max_buffers,
                config.parallelism,
                config.resolve_thread_cache_capacity(class_config.max_buffers),
                config.prefill,
            );

            // Initialize created metrics after constructor prefill.
            if config.prefill {
                let label = SizeClassLabel {
                    size_class: class_config.size.get() as u64,
                };
                metrics
                    .created
                    .get_or_create(&label)
                    .set(class_config.max_buffers.get() as i64);
            }

            let index = class_config.size.get().trailing_zeros() as usize - min_exponent;
            classes.resize(index + 1, handle);
        }

        Self {
            inner: Arc::new(BufferPoolInner {
                config,
                classes,
                min_size,
                max_size,
                metrics,
            }),
        }
    }

    /// Returns the routing index for a given size, or `None` if `size` exceeds
    /// the largest enabled class.
    ///
    /// The routing vector is exponent-indexed, so this arithmetic is identical
    /// for contiguous and sparse layouts. Disabled exponents resolve to an
    /// aliased handle for the next enabled class.
    #[inline(always)]
    fn class_index(&self, size: usize) -> Option<usize> {
        let min_size = self.inner.min_size;
        let max_size = self.inner.max_size;
        if size > max_size {
            return None;
        }
        if size <= min_size {
            return Some(0);
        }

        // Pool construction guarantees `min_size` and `max_size` are powers of
        // two. Since `min_size < size <= max_size`, `next_power_of_two()`
        // resolves to a valid routing entry and its exponent must be greater
        // than `min_size`'s exponent. Use wrapping arithmetic to avoid a
        // release overflow-check branch in this hot helper.
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
    /// Zero-capacity requests return a detached empty buffer without touching
    /// the pool.
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
        if capacity == 0 {
            return Ok(IoBufMut::default());
        }
        if capacity < self.inner.config.pool_min_size {
            return Ok(IoBufMut::with_alignment(
                capacity,
                self.inner.config.alignment,
            ));
        }

        let class_index = self
            .class_index_or_record_oversized(capacity)
            .ok_or(PoolError::Oversized)?;

        let buffer = self
            .inner
            .try_alloc(class_index, false)
            .map(|allocation| {
                // SAFETY: pooled allocations returned by the pool have an
                // initialized live lease.
                unsafe { IoBufMut::from_pooled_parts(allocation.buffer) }
            })
            .ok_or(PoolError::Exhausted)?;
        Ok(buffer)
    }

    /// Allocates a buffer with capacity for at least `capacity` bytes.
    ///
    /// The returned buffer has `len() == 0` and `capacity() >= capacity`,
    /// matching the semantics of [`IoBufMut::with_capacity`] and
    /// [`bytes::BytesMut::with_capacity`]. Use [`bytes::BufMut::put_slice`] or
    /// other [`bytes::BufMut`] methods to write data to the buffer.
    ///
    /// Zero-capacity requests return a detached empty buffer without touching
    /// the pool.
    ///
    /// If the pool can provide a buffer (capacity within limits and pool not
    /// exhausted), this returns a pooled buffer that will be returned to the
    /// pool when dropped. Requests smaller than [`BufferPoolConfig::pool_min_size`]
    /// bypass pooling and return an untracked aligned allocation. Oversized or
    /// exhausted requests also fall back to an untracked aligned heap allocation
    /// that is deallocated when dropped.
    ///
    /// Use [`Self::try_alloc`] if eligible requests must fail instead of falling
    /// back to direct allocation.
    ///
    /// # Initialization
    ///
    /// The returned buffer contains **uninitialized memory**. Do not read from
    /// it until data has been written.
    #[inline]
    pub fn alloc(&self, capacity: usize) -> IoBufMut {
        self.try_alloc(capacity).unwrap_or_else(|_| {
            let size = capacity.max(1);
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
    /// Zero-length requests return a detached empty buffer without touching
    /// the pool.
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
        if len == 0 {
            return Ok(IoBufMut::default());
        }
        if len < self.inner.config.pool_min_size {
            return Ok(IoBufMut::zeroed_with_alignment(
                len,
                self.inner.config.alignment,
            ));
        }

        let class_index = self
            .class_index_or_record_oversized(len)
            .ok_or(PoolError::Oversized)?;
        let allocation = self
            .inner
            .try_alloc(class_index, true)
            .ok_or(PoolError::Exhausted)?;
        // SAFETY: pooled allocations returned by the pool have an initialized
        // live lease.
        let mut buf = unsafe { IoBufMut::from_pooled_parts(allocation.buffer) };
        if allocation.is_new {
            // SAFETY: newly allocated zeroed buffers have `capacity() >= len`
            // and the readable bytes are initialized by zeroed allocation.
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
    /// Zero-length requests return a detached empty buffer without touching
    /// the pool.
    ///
    /// If the pool can provide a buffer (len within limits and pool not
    /// exhausted), this returns a pooled buffer that will be returned to the
    /// pool when dropped. Requests smaller than [`BufferPoolConfig::pool_min_size`]
    /// bypass pooling and return an untracked aligned allocation. Oversized or
    /// exhausted requests also fall back to an untracked aligned heap allocation
    /// that is deallocated when dropped.
    ///
    /// Use this for read APIs that require an initialized `&mut [u8]`. This
    /// avoids `unsafe set_len` at callsites.
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
            let size = len.max(1);
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

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::{
        class::tests::{
            get_global_created, get_global_len, get_global_num_stripes, get_local_len,
            get_thread_cache_capacity,
        },
        *,
    };
    use crate::{
        iobuf::{IoBuf, cache_line_size},
        telemetry::metrics::Registry,
    };
    use bytes::{Buf, BufMut};
    use commonware_utils::NZU32;
    use std::{
        sync::{Arc, mpsc},
        thread,
    };

    fn test_pool(config: BufferPoolConfig) -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(config, &mut registry)
    }

    /// Creates a test config with page alignment.
    fn test_config(min_size: usize, max_size: usize, max_per_class: u32) -> BufferPoolConfig {
        BufferPoolConfig::for_network()
            .with_pool_min_size(0)
            .with_size_class_range(
                NZUsize!(min_size),
                NZUsize!(max_size),
                NZU32!(max_per_class),
            )
            .with_alignment(NZUsize!(page_size()))
    }

    /// Creates a page-aligned test config with exactly the given classes.
    fn sparse_config(classes: impl IntoIterator<Item = (usize, u32)>) -> BufferPoolConfig {
        BufferPoolConfig::for_network()
            .with_pool_min_size(0)
            .with_size_classes(
                classes
                    .into_iter()
                    .map(|(size, max_buffers)| (NZUsize!(size), NZU32!(max_buffers))),
            )
            .with_alignment(NZUsize!(page_size()))
    }

    /// Collects the enabled classes as `(size, max_buffers)` pairs.
    fn classes_of(config: &BufferPoolConfig) -> Vec<(usize, u32)> {
        config
            .size_classes()
            .map(|class| (class.size.get(), class.max_buffers.get()))
            .collect()
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
    fn test_explicit_thread_cache_capacity_clamps_to_class_limit() {
        let page = page_size();
        // An explicit capacity above a class limit clamps to that limit
        // instead of invalidating the configuration.
        let config = test_config(page, page * 4, 10).with_max_thread_cache_capacity(NZUsize!(11));
        config.validate();
        let pool = test_pool(config);
        let class_index = pool.class_index(page).unwrap();
        assert_eq!(
            get_thread_cache_capacity(&pool.inner.classes[class_index]),
            10
        );

        // Per-class limits clamp independently: a small class cannot lower a
        // larger class's explicit capacity.
        let config = BufferPoolConfig::for_network()
            .with_size_classes([(NZUsize!(1024), NZU32!(4)), (NZUsize!(4096), NZU32!(64))])
            .with_max_thread_cache_capacity(NZUsize!(16));
        let pool = test_pool(config);
        let small_index = pool.class_index(1024).unwrap();
        let large_index = pool.class_index(4096).unwrap();
        assert_eq!(
            get_thread_cache_capacity(&pool.inner.classes[small_index]),
            4
        );
        assert_eq!(
            get_thread_cache_capacity(&pool.inner.classes[large_index]),
            16
        );
    }

    #[test]
    #[should_panic(expected = "class size must be a power of two")]
    fn test_config_invalid_min_size() {
        let _ = BufferPoolConfig::for_network().with_size_class_range(
            NZUsize!(3000),
            NZUsize!(8192),
            NZU32!(10),
        );
    }

    #[test]
    #[should_panic(expected = "class size must be a power of two")]
    fn test_config_invalid_max_size() {
        let _ = BufferPoolConfig::for_network().with_size_class_range(
            NZUsize!(4096),
            NZUsize!(12000),
            NZU32!(10),
        );
    }

    #[test]
    #[should_panic(expected = "max size must be >= min size")]
    fn test_config_range_rejects_max_below_min() {
        let _ = BufferPoolConfig::for_network().with_size_class_range(
            NZUsize!(8192),
            NZUsize!(1024),
            NZU32!(10),
        );
    }

    #[test]
    #[should_panic(expected = "class size must not exceed isize::MAX")]
    fn test_config_rejects_class_size_above_isize_max() {
        let _ = BufferPoolConfig::for_network()
            .with_size_class(NZUsize!(1usize << (usize::BITS - 1)), NZU32!(1));
    }

    #[test]
    #[should_panic(expected = "alignment must be a power of two")]
    fn test_config_invalid_alignment() {
        let page = page_size();
        let config = test_config(page, page, 10).with_alignment(NZUsize!(page - 1));
        config.validate();
    }

    #[test]
    #[should_panic(expected = "must be >= alignment")]
    fn test_config_min_size_below_alignment() {
        let page = page_size();
        let config = test_config(page, page, 10).with_alignment(NZUsize!(page * 2));
        config.validate();
    }

    #[test]
    #[should_panic(expected = "pool_min_size")]
    fn test_config_pool_min_size_above_min_size() {
        let page = page_size();
        let config = test_config(page, page, 10).with_pool_min_size(page + 1);
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
    fn test_size_classes_replacement_normalizes_and_iterates() {
        // Unsorted explicit input normalizes into ascending size order.
        let config = BufferPoolConfig::for_network().with_size_classes([
            (NZUsize!(1 << 20), NZU32!(16)),
            (NZUsize!(4096), NZU32!(1024)),
            (NZUsize!(65536), NZU32!(256)),
        ]);
        assert_eq!(
            classes_of(&config),
            vec![(4096, 1024), (65536, 256), (1 << 20, 16)]
        );
        assert_eq!(config.size_classes().len(), 3);
        assert_eq!(config.min_size().get(), 4096);
        assert_eq!(config.max_size().get(), 1 << 20);
        assert_eq!(
            config.max_tracked_bytes(),
            4096 * 1024 + 65536 * 256 + (1 << 20) * 16
        );

        // BufferPoolClassConfig values work as inputs too.
        let explicit = BufferPoolConfig::for_network().with_size_classes([BufferPoolClassConfig {
            size: NZUsize!(512),
            max_buffers: NZU32!(2),
        }]);
        assert_eq!(classes_of(&explicit), vec![(512, 2)]);
    }

    #[test]
    #[should_panic(expected = "class layout must enable at least one class")]
    fn test_size_classes_rejects_empty_input() {
        let _ = BufferPoolConfig::for_network()
            .with_size_classes(std::iter::empty::<BufferPoolClassConfig>());
    }

    #[test]
    #[should_panic(expected = "duplicate class size 4096")]
    fn test_size_classes_rejects_duplicates() {
        let _ = BufferPoolConfig::for_network()
            .with_size_classes([(NZUsize!(4096), NZU32!(1)), (NZUsize!(4096), NZU32!(2))]);
    }

    #[test]
    #[should_panic(expected = "class size must be a power of two")]
    fn test_size_classes_rejects_non_power_of_two() {
        let _ = BufferPoolConfig::for_network().with_size_classes([(NZUsize!(3000), NZU32!(1))]);
    }

    #[test]
    fn test_size_class_upsert_and_removal() {
        let base = BufferPoolConfig::for_network().with_size_class_range(
            NZUsize!(1024),
            NZUsize!(8192),
            NZU32!(8),
        );

        // Upsert replaces an enabled class's limit in place.
        let tuned = base.clone().with_size_class(NZUsize!(2048), NZU32!(64));
        assert_eq!(
            classes_of(&tuned),
            vec![(1024, 8), (2048, 64), (4096, 8), (8192, 8)]
        );

        // Upsert can also add a class outside the current span.
        let extended = base.clone().with_size_class(NZUsize!(32768), NZU32!(2));
        assert_eq!(extended.max_size().get(), 32768);
        assert_eq!(classes_of(&extended).len(), 5);

        // Removing a middle class leaves a gap.
        let sparse = base.clone().without_size_class(NZUsize!(2048));
        assert_eq!(classes_of(&sparse), vec![(1024, 8), (4096, 8), (8192, 8)]);

        // Removing an endpoint narrows the derived bounds.
        let narrowed = base.without_size_class(NZUsize!(1024));
        assert_eq!(narrowed.min_size().get(), 2048);
        let narrowed = narrowed.without_size_class(NZUsize!(8192));
        assert_eq!(narrowed.max_size().get(), 4096);

        // Uniform overwrite applies to every enabled class.
        let uniform = sparse.with_max_per_class(NZU32!(3));
        assert_eq!(classes_of(&uniform), vec![(1024, 3), (4096, 3), (8192, 3)]);
    }

    #[test]
    #[should_panic(expected = "cannot remove a class that is not enabled")]
    fn test_without_size_class_rejects_absent_class() {
        let _ = BufferPoolConfig::for_network().without_size_class(NZUsize!(1 << 30));
    }

    #[test]
    #[should_panic(expected = "cannot remove the final enabled class")]
    fn test_without_size_class_rejects_final_class() {
        let _ = BufferPoolConfig::for_network()
            .with_size_classes([(NZUsize!(4096), NZU32!(1))])
            .without_size_class(NZUsize!(4096));
    }

    #[test]
    fn test_bytes_per_class_gives_equal_byte_weight() {
        let config = BufferPoolConfig::for_network()
            .with_size_classes([
                (NZUsize!(1024), NZU32!(1)),
                (NZUsize!(4096), NZU32!(1)),
                (NZUsize!(1 << 20), NZU32!(1)),
            ])
            .with_bytes_per_class(NZUsize!(64 * 1024));
        // Classes smaller than the target get bytes/size buffers, classes
        // larger than the target floor at one buffer.
        assert_eq!(
            classes_of(&config),
            vec![(1024, 64), (4096, 16), (1 << 20, 1)]
        );

        // A target equal to the class size derives exactly one buffer.
        let exact = BufferPoolConfig::for_network()
            .with_size_classes([(NZUsize!(4096), NZU32!(7))])
            .with_bytes_per_class(NZUsize!(4096));
        assert_eq!(classes_of(&exact), vec![(4096, 1)]);
    }

    #[test]
    fn test_class_for_routes_to_smallest_fitting_class() {
        let config = BufferPoolConfig::for_network()
            .with_size_classes([(NZUsize!(4096), NZU32!(4)), (NZUsize!(32768), NZU32!(2))]);

        // Requests at or below the smallest class route to it.
        assert_eq!(config.class_for(0).unwrap().size.get(), 4096);
        assert_eq!(config.class_for(4096).unwrap().size.get(), 4096);

        // Requests in the gap route to the next enabled class, even when
        // their natural power-of-two exponent is disabled.
        assert_eq!(config.class_for(4097).unwrap().size.get(), 32768);
        assert_eq!(config.class_for(16384).unwrap().size.get(), 32768);
        assert_eq!(config.class_for(32768).unwrap().size.get(), 32768);

        // Requests above the largest class have no serving class.
        assert_eq!(config.class_for(32769), None);
    }

    #[test]
    fn test_sparse_routing_allocates_next_enabled_class() {
        // Classes `page` and `8 * page` with the two exponents between them
        // disabled: requests in the gap route forward to the larger class.
        let page = page_size();
        let pool = test_pool(sparse_config([(page, 4), (page * 8, 4)]));

        // Below the first class routes to it.
        let buf = pool.try_alloc(1).unwrap();
        assert_eq!(buf.capacity(), page);

        // Exact fit for the first class.
        let buf = pool.try_alloc(page).unwrap();
        assert_eq!(buf.capacity(), page);

        // One byte into the gap routes to the next enabled class.
        let buf = pool.try_alloc(page + 1).unwrap();
        assert_eq!(buf.capacity(), page * 8);

        // A request whose natural class is disabled routes forward too.
        let buf = pool.try_alloc(page * 4).unwrap();
        assert_eq!(buf.capacity(), page * 8);

        // Exact fit for the last class.
        let buf = pool.try_alloc(page * 8).unwrap();
        assert_eq!(buf.capacity(), page * 8);

        // Above the last class is oversized.
        assert_eq!(
            pool.try_alloc(page * 8 + 1).unwrap_err(),
            PoolError::Oversized
        );
    }

    #[test]
    fn test_sparse_routing_exhaustion_does_not_cascade() {
        let page = page_size();
        let pool = test_pool(sparse_config([(page, 1), (page * 8, 1)]));

        // Exhaust the small class. A page-sized request must report
        // exhaustion even though the larger class still has capacity.
        let _small = pool.try_alloc(page).unwrap();
        assert_eq!(pool.try_alloc(page).unwrap_err(), PoolError::Exhausted);

        // The larger class is unaffected.
        let _large = pool.try_alloc(page * 8).unwrap();

        // The untracked fallback is sized from the request rather than a pool
        // class. The aligned owner may round its usable capacity up by at most
        // seven bytes.
        let fallback = pool.alloc(page);
        assert!(!fallback.is_pooled());
        assert_eq!(fallback.capacity(), page);
        let small_fallback = pool.alloc(100);
        assert!(!small_fallback.is_pooled());
        assert!((100..108).contains(&small_fallback.capacity()));
    }

    #[test]
    fn test_sparse_metrics_use_enabled_class_labels() {
        // Metrics attribute to the enabled class that served the request, so
        // a request routed through a gap lands on the larger class's label.
        let page = page_size();
        let mut registry = Registry::default();
        let pool = BufferPool::new(sparse_config([(page, 1), (page * 8, 1)]), &mut registry);

        // Allocate through the gap, then exhaust the routed class through it.
        let _held = pool.try_alloc(page * 2).unwrap();
        assert!(pool.try_alloc(page * 2).is_err());
        // Request above the largest class records an oversized attempt.
        assert!(pool.try_alloc(page * 16).is_err());

        let encoded = registry.encode();
        // Both created and exhausted count against the larger class, and the
        // disabled exponent of the natural request never appears as a label.
        assert!(
            encoded.contains(&format!(
                "buffer_pool_created{{size_class=\"{}\"}} 1",
                page * 8
            )),
            "metrics output: {encoded}"
        );
        assert!(
            encoded.contains(&format!(
                "buffer_pool_exhausted_total{{size_class=\"{}\"}} 1",
                page * 8
            )),
            "metrics output: {encoded}"
        );
        assert!(
            !encoded.contains(&format!("size_class=\"{}\"", page * 2)),
            "metrics output: {encoded}"
        );
        assert!(
            encoded.contains("buffer_pool_oversized_total 1"),
            "metrics output: {encoded}"
        );
    }

    #[test]
    fn test_sparse_gap_allocations_share_one_class() {
        // Requests routed through a gap and requests hitting the class
        // directly must share the same allocator, TLS cache, and metrics.
        let page = page_size();
        let pool = test_pool(sparse_config([(page, 4), (page * 8, 4)]));

        // All gap exponents alias the same class as the direct exponent.
        let direct = pool.class_index(page * 8).unwrap();
        for size in [page + 1, page * 2, page * 4, page * 8] {
            let index = pool.class_index(size).unwrap();
            assert!(
                pool.inner.classes[index].same_class(&pool.inner.classes[direct]),
                "size {size} must alias the largest class"
            );
        }

        // A buffer allocated through the gap returns to the aliased class and
        // is reusable through the direct route.
        let mut via_gap = pool.try_alloc(page * 2).unwrap();
        let ptr = via_gap.as_mut_ptr();
        drop(via_gap);
        let mut direct_reuse = pool.try_alloc(page * 8).unwrap();
        assert_eq!(direct_reuse.as_mut_ptr(), ptr);
    }

    #[test]
    fn test_sparse_pool_drop_drains_each_unique_class_once() {
        // Dropping a sparse pool must reclaim globally parked buffers exactly
        // as the contiguous pool does, draining each unique class once even
        // though several routing entries alias it.
        let page = page_size();
        let pool =
            test_pool(sparse_config([(page, 2), (page * 16, 2)]).with_thread_cache_disabled());

        let class_index = pool.class_index(page * 16).unwrap();
        // Keep a test-owned handle so the class remains inspectable after
        // the pool is dropped below.
        let class = pool.inner.classes[class_index].clone();

        // Park one buffer allocated through the gap in the global freelist.
        let buf = pool.try_alloc(page * 2).unwrap();
        drop(buf);
        assert_eq!(get_global_len(&class), 1);

        drop(pool);
        assert_eq!(get_global_len(&class), 0);
        assert_eq!(get_global_created(&class), 1);
    }

    #[test]
    fn test_sparse_pool_debug_reports_unique_classes() {
        let page = page_size();
        let pool = test_pool(sparse_config([(page, 2), (page * 16, 2)]));
        // Two enabled classes span five exponents, Debug must report two.
        assert_eq!(pool.inner.classes.len(), 5);
        let debug = format!("{pool:?}");
        assert!(debug.contains("num_classes: 2"), "debug output: {debug}");
    }

    #[test]
    fn test_sparse_prefill_creates_per_class_limits() {
        let page = page_size();
        let pool = test_pool(sparse_config([(page, 3), (page * 4, 1)]).with_prefill(true));

        // Each unique class prefilled exactly its own limit, aliases add none.
        let small = &pool.inner.classes[pool.class_index(page).unwrap()];
        let large = &pool.inner.classes[pool.class_index(page * 4).unwrap()];
        assert_eq!(get_global_created(small), 3);
        assert_eq!(get_global_len(small), 3);
        assert_eq!(get_global_created(large), 1);
        assert_eq!(get_global_len(large), 1);

        // Prefilled capacity is immediately allocatable and bounded.
        let a = pool.try_alloc(page).unwrap();
        let b = pool.try_alloc(page).unwrap();
        let c = pool.try_alloc(page).unwrap();
        assert!(pool.try_alloc(page).is_err());
        drop((a, b, c));
        let _gap = pool.try_alloc(page * 2).unwrap();
        assert!(pool.try_alloc(page * 4).is_err());
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
        let pool = test_pool(
            BufferPoolConfig::for_network()
                .with_pool_min_size(512)
                .with_size_class_range(NZUsize!(512), NZUsize!(1024), NZU32!(2))
                .with_alignment(NZUsize!(128)),
        );

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
    fn test_zero_capacity_requests_bypass_pool() {
        // A single-slot pool: if a zero-capacity request claimed a buffer,
        // the follow-up real allocation would fail with Exhausted.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 1));

        let empty = pool.try_alloc(0).unwrap();
        assert!(!empty.is_pooled());
        assert_eq!(empty.capacity(), 0);

        let zeroed = pool.try_alloc_zeroed(0).unwrap();
        assert!(!zeroed.is_pooled());
        assert_eq!(zeroed.len(), 0);
        assert_eq!(zeroed.capacity(), 0);

        assert_eq!(pool.alloc(0).capacity(), 0);
        assert_eq!(pool.alloc_zeroed(0).len(), 0);

        let real = pool.try_alloc(page).unwrap();
        assert!(real.is_pooled());
        assert_eq!(real.capacity(), page);
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
        let pool = test_pool(
            BufferPoolConfig::for_network()
                .with_pool_min_size(0)
                .with_size_class_range(page, page, NZU32!(5))
                .with_alignment(page)
                .with_prefill(true),
        );

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
        assert_eq!(config.pool_min_size, 0);
        assert_eq!(config.min_size().get(), 1024);
        assert_eq!(config.max_size().get(), 128 * 1024);
        let expected: Vec<(usize, u32)> = (10..=17).map(|e| (1usize << e, 4096)).collect();
        assert_eq!(classes_of(&config), expected);
        assert_eq!(config.parallelism, NZUsize!(1));
        assert_eq!(
            config.thread_cache_config,
            BufferPoolThreadCacheConfig::Enabled(None)
        );
        assert!(!config.prefill);
        assert_eq!(config.alignment.get(), 1);
    }

    #[test]
    fn test_config_for_storage() {
        let config = BufferPoolConfig::for_storage();
        config.validate();
        assert_eq!(config.pool_min_size, 0);
        assert_eq!(config.min_size().get(), page_size());
        assert_eq!(config.max_size().get(), 8 * 1024 * 1024);
        let min_exponent = page_size().trailing_zeros();
        let expected: Vec<(usize, u32)> = (min_exponent..=23).map(|e| (1usize << e, 64)).collect();
        assert_eq!(classes_of(&config), expected);
        assert_eq!(config.parallelism, NZUsize!(1));
        assert_eq!(
            config.thread_cache_config,
            BufferPoolThreadCacheConfig::Enabled(None)
        );
        assert!(!config.prefill);
        assert_eq!(config.alignment.get(), 1);
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
            .with_parallelism(NZUsize!(4))
            .with_max_thread_cache_capacity(NZUsize!(8))
            .with_prefill(true)
            .with_size_class_range(page, NZUsize!(128 * 1024), NZU32!(64));

        config.validate();
        assert_eq!(config.pool_min_size, 1024);
        assert_eq!(config.min_size(), page);
        assert_eq!(config.max_size().get(), 128 * 1024);
        assert!(
            config
                .size_classes()
                .all(|class| class.max_buffers.get() == 64)
        );
        assert_eq!(config.parallelism, NZUsize!(4));
        assert_eq!(
            config.thread_cache_config,
            BufferPoolThreadCacheConfig::Enabled(Some(NZUsize!(8)))
        );
        assert!(config.prefill);
        assert_eq!(config.alignment.get(), 1);

        // Alignment can be tuned explicitly as long as the smallest class is
        // also adjusted.
        let aligned = BufferPoolConfig::for_network()
            .with_pool_min_size(256)
            .with_parallelism(NZUsize!(4))
            .with_alignment(NZUsize!(256))
            .with_size_class_range(NZUsize!(256), NZUsize!(128 * 1024), NZU32!(4096));
        aligned.validate();
        assert_eq!(aligned.parallelism, NZUsize!(4));
        assert_eq!(
            aligned.thread_cache_config,
            BufferPoolThreadCacheConfig::Enabled(None)
        );
        assert_eq!(aligned.alignment.get(), 256);
        assert_eq!(aligned.min_size().get(), 256);
    }

    #[test]
    fn test_parallelism_policy_resolves_thread_cache_capacity() {
        let page = page_size();

        // Half the class budget is divided across expected threads.
        let pool = test_pool(test_config(page, page, 64).with_parallelism(NZUsize!(8)));
        let class_index = pool.class_index(page).unwrap();
        assert_eq!(
            get_thread_cache_capacity(&pool.inner.classes[class_index]),
            4
        );

        // Large classes scale past the previous eight-slot cap.
        let pool = test_pool(test_config(page, page, 4096).with_parallelism(NZUsize!(8)));
        let class_index = pool.class_index(page).unwrap();
        assert_eq!(
            get_thread_cache_capacity(&pool.inner.classes[class_index]),
            256
        );
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
        assert_eq!(get_thread_cache_capacity(class), 0);

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
        assert_eq!(get_global_num_stripes(&pool.inner.classes[class_index]), 16);

        // When expected parallelism rounds above capacity, the freelist caps
        // stripes so every stripe can contain at least one slot.
        let pool = test_pool(test_config(page, page, 12).with_parallelism(NZUsize!(9)));

        let class_index = pool.class_index(page).unwrap();
        assert_eq!(get_global_num_stripes(&pool.inner.classes[class_index]), 8);

        // Disabling thread-local caches should not change global striping.
        let pool = test_pool(
            test_config(page, page, 64)
                .with_parallelism(NZUsize!(16))
                .with_thread_cache_disabled(),
        );

        let class_index = pool.class_index(page).unwrap();
        assert_eq!(get_global_num_stripes(&pool.inner.classes[class_index]), 16);
    }

    #[test]
    fn test_fixed_thread_cache_capacity_overrides_auto_capacity() {
        let page = page_size();
        let pool = test_pool(
            test_config(page, page, 64)
                .with_parallelism(NZUsize!(8))
                .with_max_thread_cache_capacity(NZUsize!(7)),
        );
        let class_index = pool.class_index(page).unwrap();

        // Fixed capacity should bypass the derived parallelism heuristic.
        assert_eq!(
            get_thread_cache_capacity(&pool.inner.classes[class_index]),
            7
        );
        assert_eq!(get_global_num_stripes(&pool.inner.classes[class_index]), 8);
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
        assert_eq!(get_thread_cache_capacity(class), 0);
        assert_eq!(get_local_len(class), 0);
        assert_eq!(get_global_len(class), 1);
    }

    #[test]
    fn test_config_with_budget_bytes() {
        // Classes: 4, 8, 16 (sum = 28). Budget 280 scales the uniform shape
        // to exactly 10 buffers per class.
        let base = BufferPoolConfig::for_network().with_size_class_range(
            NZUsize!(4),
            NZUsize!(16),
            NZU32!(1),
        );
        let config = base.clone().with_budget_bytes(NZUsize!(280));
        assert_eq!(classes_of(&config), vec![(4, 10), (8, 10), (16, 10)]);
        assert_eq!(config.max_tracked_bytes(), 280);

        // The budget is a strict ceiling: 279 cannot afford the tenth round.
        let config = base.clone().with_budget_bytes(NZUsize!(279));
        assert_eq!(classes_of(&config), vec![(4, 9), (8, 9), (16, 9)]);

        // The minimum footprint keeps one buffer per class.
        let config = base.clone().with_budget_bytes(NZUsize!(28));
        assert_eq!(classes_of(&config), vec![(4, 1), (8, 1), (16, 1)]);

        // Scaling preserves a nonuniform shape proportionally: limits (4, 1)
        // over sizes (4, 16) cost 32 per round, so budget 96 affords a 3x
        // scale of the whole shape.
        let shaped_base = BufferPoolConfig::for_network()
            .with_size_classes([(NZUsize!(4), NZU32!(4)), (NZUsize!(16), NZU32!(1))]);
        let shaped = shaped_base.clone().with_budget_bytes(NZUsize!(96));
        assert_eq!(classes_of(&shaped), vec![(4, 12), (16, 3)]);

        // Scaling can also shrink an existing shape.
        let shrunk = shaped_base.with_budget_bytes(NZUsize!(20));
        assert_eq!(classes_of(&shrunk), vec![(4, 1), (16, 1)]);

        // Rounding never disables a class, so an uneven budget leaves an
        // intentionally unused remainder.
        let uneven = base.with_budget_bytes(NZUsize!(30));
        assert_eq!(classes_of(&uneven), vec![(4, 1), (8, 1), (16, 1)]);
    }

    #[test]
    fn test_config_with_budget_bytes_is_one_shot() {
        // The budget is not a stored policy: later builder calls apply to the
        // scaled limits and may exceed the former budget.
        let config = BufferPoolConfig::for_network()
            .with_size_class_range(NZUsize!(4), NZUsize!(16), NZU32!(1))
            .with_budget_bytes(NZUsize!(280));
        assert_eq!(config.max_tracked_bytes(), 280);

        let overridden = config.clone().with_max_per_class(NZU32!(100));
        assert_eq!(overridden.max_tracked_bytes(), 2800);

        let upserted = config.with_size_class(NZUsize!(32), NZU32!(100));
        assert_eq!(upserted.max_tracked_bytes(), 280 + 32 * 100);

        // Rescaling applies to the already scaled limits, not the shape they
        // were derived from, so repeating a budget can compound the rounding
        // floors into a slightly different shape.
        let base = BufferPoolConfig::for_network()
            .with_size_classes([(NZUsize!(1), NZU32!(3)), (NZUsize!(8), NZU32!(2))]);
        let once = base.with_budget_bytes(NZUsize!(21));
        assert_eq!(classes_of(&once), vec![(1, 4), (8, 2)]);
        let twice = once.with_budget_bytes(NZUsize!(21));
        assert_eq!(classes_of(&twice), vec![(1, 5), (8, 2)]);
    }

    #[test]
    #[should_panic(expected = "budget must cover at least one buffer from every enabled class")]
    fn test_config_with_budget_bytes_below_minimum() {
        let _ = BufferPoolConfig::for_network()
            .with_size_class_range(NZUsize!(4), NZUsize!(16), NZU32!(1))
            .with_budget_bytes(NZUsize!(27));
    }

    #[test]
    #[should_panic(expected = "budget requires scaling a class limit above u32::MAX")]
    fn test_config_with_budget_bytes_above_u32() {
        // One-byte class: any budget beyond u32::MAX buffers must panic
        // instead of silently capping the limit.
        let _ = BufferPoolConfig::for_network()
            .with_size_classes([(NZUsize!(1), NZU32!(1))])
            .with_budget_bytes(NZUsize!(u32::MAX as usize + 2));
    }

    #[test]
    fn test_config_with_budget_bytes_near_u32_breakpoints() {
        // Two classes with limits near u32::MAX exercise the tightest
        // count-change breakpoint separation the Q64.64 scale must resolve.
        // Reduce the budget under miri so the brute-force reference stays
        // fast in the interpreter.
        cfg_if::cfg_if! {
            if #[cfg(miri)] {
                let budget = 10_000usize;
            } else {
                let budget = 1_000_000usize;
            }
        }
        let a = u32::MAX;
        let b = u32::MAX - 1;
        let config = BufferPoolConfig::for_network()
            .with_size_classes([
                (NZUsize!(1), NonZeroU32::new(a).unwrap()),
                (NZUsize!(2), NonZeroU32::new(b).unwrap()),
            ])
            .with_budget_bytes(NonZeroUsize::new(budget).unwrap());
        // Brute-force the optimal proportional vector along the scale axis.
        let expected = brute_force_budget(&[(1, a), (2, b)], budget as u128);
        assert_eq!(
            classes_of(&config)
                .into_iter()
                .map(|(_, limit)| limit)
                .collect::<Vec<_>>(),
            expected
        );
    }

    /// Reference implementation of proportional budget scaling.
    ///
    /// Walks the count vectors produced along the scale axis in breakpoint
    /// order and returns the last one whose total fits the budget.
    fn brute_force_budget(shape: &[(usize, u32)], budget: u128) -> Vec<u32> {
        // Collect candidate scales k/c for every class and every count k the
        // budget could possibly afford, then evaluate the count vector at each.
        let mut best: Option<Vec<u32>> = None;
        let mut best_total = 0u128;
        let mut candidates: Vec<(u128, u128)> = vec![(0, 1)];
        for &(size, limit) in shape {
            let max_count = (budget / size as u128).min(u32::MAX as u128);
            for k in 1..=max_count {
                candidates.push((k, limit as u128));
            }
        }
        for (k, c) in candidates {
            // counts_i = max(1, floor(c_i * k / c))
            let counts: Vec<u128> = shape
                .iter()
                .map(|&(_, limit)| ((limit as u128 * k) / c).max(1))
                .collect();
            if counts.iter().any(|&count| count > u32::MAX as u128) {
                continue;
            }
            let total: u128 = counts
                .iter()
                .zip(shape.iter())
                .map(|(&count, &(size, _))| count * size as u128)
                .sum();
            // Candidate vectors are componentwise ordered along the scale
            // axis, so the maximal fitting total identifies a unique vector.
            if total <= budget && total >= best_total {
                best_total = total;
                best = Some(counts.iter().map(|&count| count as u32).collect());
            }
        }
        best.expect("budget covers one buffer per class")
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
        assert_eq!(pool.config().min_size().get(), page);
    }

    #[test]
    fn test_pooled_debug_and_empty_freeze_paths() {
        // Debug formatting for pooled mutable/immutable handles, and empty
        // freeze should detach without retaining the pool allocation.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 3));

        let pooled_mut = pool.try_alloc(page).expect("pooled allocation");
        let pooled_mut_debug = format!("{pooled_mut:?}");
        assert!(pooled_mut_debug.contains("IoBufMut"));
        assert!(pooled_mut_debug.contains("cap"));
        assert!(pooled_mut.is_pooled());

        let empty = pool.try_alloc(page).expect("pooled allocation").freeze();
        assert!(empty.is_empty());
        assert!(!empty.is_pooled());

        let mut non_empty = pool.try_alloc(page).expect("pooled allocation");
        non_empty.put_slice(b"abc");
        let pooled = non_empty.freeze();
        let pooled_debug = format!("{pooled:?}");
        assert!(pooled_debug.contains("IoBuf"));
        assert!(pooled_debug.contains("pooled"));
        assert!(pooled.is_pooled());

        BufferPoolThreadCache::flush();
    }

    #[test]
    fn test_freeze_returns_buffer_to_pool() {
        let page = page_size();
        let pool = test_pool(test_config(page, page, 2));

        // Initially: 0 allocated, 0 available
        assert_eq!(get_allocated(&pool, page), 0);
        assert_eq!(get_available(&pool, page), 0);

        // Allocate, write, and freeze. Empty freeze deliberately detaches from
        // the pool, so this test keeps a non-empty immutable view alive.
        let mut buf = pool.try_alloc(page).unwrap();
        buf.put_slice(b"x");
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

        let mut buf = pool.try_alloc(page).unwrap();
        buf.put_slice(b"non-full");
        assert_eq!(get_allocated(&pool, page), 1);

        let iobuf = buf.freeze();
        assert_eq!(iobuf.len(), 8);
        assert_eq!(get_allocated(&pool, page), 1);

        let iobufmut: IoBufMut = iobuf.into();
        assert_eq!(iobufmut.as_ref(), b"non-full");

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
                    let mut buf = pool.try_alloc(page).unwrap();
                    // Write a byte so freeze produces a live pooled owner
                    // (freezing an empty buffer detaches and releases it,
                    // which would leave the refcount protocol unexercised).
                    buf.put_slice(b"x");
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
            let mut buf = pool.try_alloc(page).unwrap();
            buf.put_slice(b"x");
            let iobuf = buf.freeze();
            tx.send(iobuf).unwrap();
        }
        drop(tx);

        // Receive and drop on another thread. Cross-thread returns initialize
        // the dropping thread's local cache, so the buffers remain local to that
        // thread instead of bouncing through the global freelist.
        let handle = thread::spawn(move || {
            while let Ok(iobuf) = rx.recv() {
                drop(iobuf);
            }

            let class_index = pool
                .class_index(page)
                .expect("class exists for page-sized buffer");
            assert_eq!(get_local_len(&pool.inner.classes[class_index]), 50);
            assert_eq!(get_global_len(&pool.inner.classes[class_index]), 0);

            for _ in 0..50 {
                let _buf = pool
                    .try_alloc(page)
                    .expect("dropping thread should be able to reuse locally returned buffers");
            }
        });

        handle.join().unwrap();
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
    fn test_pool_metrics_track_created_exhausted_oversized() {
        let page = page_size();
        let mut registry = Registry::default();
        let pool = BufferPool::new(test_config(page, page, 1), &mut registry);

        // One created buffer, then exhaustion, then an oversized request.
        let buf = pool.try_alloc(page).unwrap();
        assert_eq!(pool.try_alloc(page).unwrap_err(), PoolError::Exhausted);
        assert_eq!(pool.try_alloc(page * 2).unwrap_err(), PoolError::Oversized);

        let encoded = registry.encode();
        assert!(
            encoded.contains(&format!("buffer_pool_created{{size_class=\"{page}\"}} 1")),
            "created gauge missing: {encoded}"
        );
        assert!(
            encoded.contains(&format!(
                "buffer_pool_exhausted_total{{size_class=\"{page}\"}} 1"
            )),
            "exhausted counter missing: {encoded}"
        );
        assert!(
            encoded.contains("buffer_pool_oversized_total 1"),
            "oversized counter missing: {encoded}"
        );
        drop(buf);
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

        // Fallback via alloc() when exhausted - still aligned, but untracked,
        // and sized from the requested capacity.
        let mut fallback_exhausted = pool.alloc(page);
        assert!(!fallback_exhausted.is_pooled());
        assert!((fallback_exhausted.as_mut_ptr() as usize).is_multiple_of(page));
        assert_eq!(fallback_exhausted.capacity(), page);

        let fallback_small = pool.alloc(100);
        assert!(!fallback_small.is_pooled());
        assert!((100..108).contains(&fallback_small.capacity()));

        // Fallback via alloc() when oversized - still aligned, but untracked.
        let mut fallback_oversized = pool.alloc(page * 10);
        assert!(!fallback_oversized.is_pooled());
        assert!((fallback_oversized.as_mut_ptr() as usize).is_multiple_of(page));
        assert_eq!(fallback_oversized.capacity(), page * 10);

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

        let mut pooled = pool.try_alloc(page).unwrap();
        pooled.put_slice(b"x");
        let pooled = pooled.freeze();
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

        // Reduce the class limits under miri (atomics are slow)
        cfg_if::cfg_if! {
            if #[cfg(miri)] {
                let storage_config = BufferPoolConfig::for_storage()
                    .with_alignment(NZUsize!(page))
                    .with_max_per_class(NZU32!(32));
                let network_config = BufferPoolConfig::for_network()
                    .with_alignment(NZUsize!(cache_line))
                    .with_max_per_class(NZU32!(32));
            } else {
                let storage_config = BufferPoolConfig::for_storage()
                    .with_alignment(NZUsize!(page));
                let network_config = BufferPoolConfig::for_network()
                    .with_alignment(NZUsize!(cache_line));
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

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use crate::telemetry::metrics::Registry;
    use bytes::BufMut;
    use loom::thread;

    // Models the pooled buffer lifecycle across threads: checkout, freeze,
    // clone, cross-thread final drop, and reuse from the same pool. Whichever
    // thread drops last must return the buffer to the global freelist with
    // the refcount sentinel intact so the next checkout works without
    // reinitialization. The thread cache is disabled so the return path is
    // the loom-modeled global freelist rather than OS thread-local state,
    // which loom cannot reset between interleavings.
    #[test]
    fn freeze_clone_cross_thread_drop_then_reuse() {
        loom::model(|| {
            let mut registry = Registry::default();
            let config = BufferPoolConfig::for_network()
                .with_size_class_range(NZUsize!(64), NZUsize!(64), NZU32!(2))
                .with_thread_cache_disabled();
            let pool = BufferPool::new(config, &mut registry);

            let mut buf = pool.alloc(64);
            assert!(buf.is_pooled());
            buf.put_slice(b"payload");
            let frozen = buf.freeze();
            let clone = frozen.clone();

            let t = thread::spawn(move || {
                assert_eq!(clone.as_ref(), b"payload");
                drop(clone);
            });
            assert_eq!(frozen.as_ref(), b"payload");
            drop(frozen);
            t.join().unwrap();

            // The buffer returned through whichever drop was final. Checkout
            // must succeed and expose a writable buffer again.
            let mut again = pool.alloc(64);
            assert!(again.is_pooled());
            again.put_slice(b"reuse");
            assert_eq!(again.as_ref(), b"reuse");
        });
    }

    // Models the teardown edge: a pooled buffer's final drop (which parks the
    // buffer and then releases its size-class lease) racing the public pool's
    // drop (which drains the global freelist and then releases the pool-owned
    // class reference). Whichever release is last drops the SizeClass and its
    // freelist. Parking strictly before releasing is what keeps the freelist
    // alive until the return finishes publishing under its stripe lock. Loom
    // performs no liveness check when tracked state is dropped, so swapping
    // that order manifests as a use-after-free of the freed freelist state.
    // This corrupts Loom's internal object state and is caught by its internal
    // assertions in practice. The Loom-tracked class strong count still
    // verifies the release accounting itself.
    #[test]
    fn final_drop_races_pool_teardown() {
        loom::model(|| {
            let mut registry = Registry::default();
            let config = BufferPoolConfig::for_network()
                .with_size_class_range(NZUsize!(64), NZUsize!(64), NZU32!(1))
                .with_thread_cache_disabled();
            let pool = BufferPool::new(config, &mut registry);

            let mut buf = pool.alloc(64);
            assert!(buf.is_pooled());
            buf.put_slice(b"x");
            let frozen = buf.freeze();

            let t = thread::spawn(move || drop(frozen));
            drop(pool);
            t.join().unwrap();
        });
    }

    // Models a re-checkout racing the final drop of a shared pooled buffer.
    // The final drop leaves the refcount at the sentinel (the losing handle's
    // Release decrement lands on 1, or the race-final path re-stores it with
    // a Relaxed store) before the freelist's Release publication. A
    // successful concurrent take must observe that sentinel (asserted in
    // Freelist::claim under loom) before handing the slot to a new mutable
    // handle.
    #[test]
    fn final_drop_races_recheckout() {
        loom::model(|| {
            let mut registry = Registry::default();
            let config = BufferPoolConfig::for_network()
                .with_size_class_range(NZUsize!(64), NZUsize!(64), NZU32!(1))
                .with_thread_cache_disabled();
            let pool = BufferPool::new(config, &mut registry);

            let mut buf = pool.alloc(64);
            assert!(buf.is_pooled());
            buf.put_slice(b"x");
            let frozen = buf.freeze();
            let clone = frozen.clone();

            let t = thread::spawn(move || drop(clone));
            drop(frozen);

            // The single slot may still be checked out (Exhausted) or already
            // returned by whichever drop was final. A successful claim must
            // expose a writable buffer with the sentinel restored.
            if let Ok(mut again) = pool.try_alloc(64) {
                assert!(again.is_pooled());
                again.put_slice(b"y");
                assert_eq!(again.as_ref(), b"y");
            }
            t.join().unwrap();
        });
    }
}
