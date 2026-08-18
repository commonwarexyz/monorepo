//! Buffer-pool size classes and thread-local caching.
//!
//! A size class owns buffers of one fixed capacity and a shared global
//! freelist. Each thread may cache a bounded number of buffers per size class,
//! allocations check that cache before the global freelist, and returned
//! buffers spill back to the global freelist when the cache is full or the
//! thread exits.

use super::Freelist;
use crate::iobuf::owner::{PooledBuffer, PooledOwner};
use std::{
    cell::{Cell, UnsafeCell},
    mem::MaybeUninit,
    num::{NonZeroU32, NonZeroUsize},
    ptr,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::Arc;
    } else {
        use std::sync::Arc;
    }
}

/// Minimum thread-local cache capacity required before refill/spill batches.
///
/// Below this threshold TLS still provides same-thread locality, but batching
/// would degrade to single-buffer moves and add policy complexity without
/// amortizing shared-queue traffic.
const MIN_TLS_BATCH_CAPACITY: usize = 4;

/// Per-size-class state.
///
/// Each class is a small two-level allocator:
/// - a shared global freelist for tracked buffers visible to all threads
/// - a per-thread local cache for same-thread reuse
///
/// The global freelist owns the allocation layout, slot reservation counter,
/// and side-table slots for this class. A tracked buffer can be globally parked,
/// owned by a pooled backing, or parked in one thread's local cache, but the
/// slot always belongs to this `SizeClass`.
///
/// Liveness follows the buffer ownership state. Global freelist entries carry
/// no per-buffer strong reference and rely on the pool's [`SizeClassHandle`]
/// while the pool is alive. Pooled backing values and thread-local cache
/// entries carry a live [`SizeClassLease`] in the pooled slot. Those
/// non-global states are what allow a buffer to outlive the public
/// [`super::BufferPool`] handle and still return to the correct freelist.
///
/// The freelist is the only place that deallocates tracked buffers. Returning a
/// buffer to the freelist transfers buffer ownership back to that freelist and
/// releases the slot lease that kept the class alive while the buffer was
/// outside the global freelist.
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
///   [`SizeClassHandle`] in [`super::BufferPoolInner::classes`] keeps the class alive.
/// - Pooled view: the buffer is owned by mutable or immutable I/O view state
///   and carries one [`SizeClassLease`], which is one strong reference to the
///   class.
/// - Thread-local cache: each initialized [`TlsSizeClassCacheEntry`] owns a
///   [`PooledBuffer`] whose side-table slot contains a live
///   [`SizeClassLease`]. Increasing or decreasing the cache `len` moves entries
///   into or out of the initialized prefix, but does not touch the `Arc` strong
///   count.
///
/// Moving a buffer from the global freelist to pooled view or TLS state retains
/// one class reference. Moving it back to the global freelist releases that
/// reference. Moving between pooled view and TLS state transfers the same
/// reference without touching the refcount:
///
/// ```text
///                      lease_into: retain class ref into slot lease
/// +-------------------+                             +-----------------+
/// | parked in global  | --------------------------> | checked out     |
/// | freelist          |                             | (pooled view)   |
/// | (no per-buffer    |                             +-----------------+
/// | ref: the pool's   |                       cache pop ^   | move buffer,
/// | SizeClassHandle   |                                 |   v lease stays
/// | keeps class       |                             +-----------------+
/// | alive)            | <-------------------------- | parked in TLS   |
/// +-------------------+  return_global[_batch]:     | cache           |
///                        park, THEN release lease   +-----------------+
/// ```
///
/// A checked-out buffer can also return directly to the global freelist
/// (thread caching disabled, tiny-cache overflow, or TLS unavailable during
/// thread teardown) through the same park-then-release transition.
///
/// Dropping the public [`super::BufferPool`] drains globally parked buffers, then
/// drops its `SizeClassHandle`s. Pooled views and non-empty TLS caches may keep
/// the `SizeClass` alive after that point. Empty TLS caches keep no size-class
/// reference. A later return of an outstanding buffer can recreate the cache
/// from the live lease in that buffer's slot.
///
/// This is the one raw pointer shape used by all pool-owned, pooled view, and
/// thread-local references to a [`SizeClass`]. The pointer is always derived
/// from [`Arc::into_raw`].
///
/// `SizeClassToken` itself owns nothing. It is only an identity token and raw
/// pointer accepted by the `Arc` refcount APIs:
/// - [`SizeClassHandle`] pairs a token with ownership of one strong reference.
/// - [`SizeClassLease`] pairs a token with ownership of one strong reference.
/// - [`TlsSizeClassCache`] stores entries whose pooled slots own strong
///   references through live leases.
///
/// Because the token is non-owning, code may dereference it or adjust the
/// strong count only when another invariant proves the allocation is still
/// live. [`SizeClassHandle`] and [`SizeClassLease`] prove liveness through
/// owned strong references. A non-empty [`TlsSizeClassCache`] proves liveness
/// through the live leases stored in its entries' pooled slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
struct SizeClassToken {
    ptr: ptr::NonNull<SizeClass>,
}

impl SizeClassToken {
    /// Creates a raw token for a newly allocated size class.
    ///
    /// `Arc::into_raw` leaves one outstanding strong reference behind the
    /// pointer. The returned token is still non-owning: the caller must
    /// immediately place it in an owning wrapper, such as [`SizeClassHandle`],
    /// or otherwise arrange for that strong reference to be released.
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
/// while the [`super::BufferPoolInner`] exists. Dropping the handle releases that
/// pool-owned strong reference. A class may still outlive the handle if pooled
/// backing values or thread-local cache entries own additional references
/// through live [`SizeClassLease`] values in pooled slots.
///
/// Functionally this is an `Arc<SizeClass>` stored in raw-token form. It exists
/// to keep the pool-owned reference alive and to provide a live token for
/// allocation paths that need to retain pooled-slot lease references. The raw
/// form keeps the already-loaded class pointer usable for
/// explicit refcount operations without calling [`Arc::as_ptr`] or storing a
/// second token alongside an `Arc`.
#[repr(transparent)]
pub(super) struct SizeClassHandle {
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
    pub(super) fn new(
        class_id: usize,
        size: usize,
        alignment: usize,
        max: NonZeroU32,
        parallelism: NonZeroUsize,
        thread_cache_capacity: usize,
        prefill: bool,
    ) -> Self {
        let layout = PooledOwner::layout(size, alignment);
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

    /// Creates a new tracked buffer and initializes its live lease.
    #[inline(always)]
    pub(super) fn try_create(&self, zeroed: bool) -> Option<PooledBuffer> {
        let buffer = self.global.try_create(zeroed)?;
        Some(self.lease_into(buffer))
    }

    /// Takes a parked buffer from the class-global freelist and installs its
    /// live lease.
    #[inline(always)]
    fn take_global(&self) -> Option<PooledBuffer> {
        let buffer = self.global.take()?;
        Some(self.lease_into(buffer))
    }

    /// Installs a retained class reference as a buffer's live lease.
    ///
    /// This is the single transition from lease-free pool states (just
    /// created, or parked in the global freelist) to checked-out state, so
    /// the retain plus `init_lease` pairing cannot drift between call sites.
    #[inline(always)]
    fn lease_into(&self, mut buffer: PooledBuffer) -> PooledBuffer {
        let lease = SizeClassLease::retain(self);
        // SAFETY: freshly created buffers and buffers taken from the global
        // freelist do not carry a live lease.
        unsafe { buffer.init_lease(lease) };
        buffer
    }

    /// Returns the allocation size represented by this class.
    #[inline(always)]
    pub(super) fn size(&self) -> usize {
        self.size
    }

    /// Returns whether two handles refer to the same size class.
    #[inline(always)]
    pub(super) fn same_class(&self, other: &Self) -> bool {
        self.token == other.token
    }

    /// Drains all buffers currently parked in the global freelist.
    #[inline(always)]
    pub(super) fn drain_global(&self) {
        self.global.drain();
    }
}

impl Clone for SizeClassHandle {
    fn clone(&self) -> Self {
        // SAFETY: this handle owns one strong reference for `self.token`, so
        // the class is live and a new strong reference can be retained for
        // the returned handle.
        unsafe { self.token.retain() };
        Self { token: self.token }
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
/// [`SizeClass`] alive so it can be returned after the [`super::BufferPool`] handle is
/// dropped. This is one strong `Arc<SizeClass>` reference represented by a
/// [`SizeClassToken`], with retain and release performed explicitly at the
/// boundaries where a buffer enters or leaves global pool state.
///
/// Lifetime-wise this is the same kind of reference as [`SizeClassHandle`]:
/// both own exactly one strong reference for a token. The types are separate
/// because they live in different state machines. `SizeClassHandle` is ordinary
/// RAII ownership for the pool's class vector. `SizeClassLease` is hot-path
/// pooled ownership that lives in the pooled slot while a buffer is
/// checked out or parked in a thread-local cache. It must be explicitly
/// returned to the global freelist when the buffer leaves local ownership.
///
/// The raw representation matters because the hot path mostly transfers
/// ownership between pooled view state and this thread's local cache. A real
/// `Arc<SizeClass>` field is pointer-sized too, but it is a non-`Copy` value
/// with drop glue. Even when the strong count would not change, moving it
/// through pooled buffer and cache-entry structs makes the compiler preserve
/// destructor paths for those structs. `SizeClassLease` has no automatic drop:
/// moving between checked-out view and local-cache state is just moving the
/// pooled buffer whose slot contains the lease. Only explicit calls such as
/// [`Self::return_global`] adjust the strong count.
///
/// A lease must be consumed when a buffer returns to the global freelist.
/// Because this type intentionally has no `Drop` implementation, simply
/// dropping a lease value would leak the strong reference. The hot local
/// alloc/drop loop therefore keeps the lease in the slot and avoids moving a
/// separate lease value at all.
///
/// Thread-local cache entries store a [`PooledBuffer`] whose slot lease stays
/// live. Popping from the local cache hands that same live lease back to the
/// caller without touching the strong count.
///
/// Globally parked buffers do not carry a class reference: taking from the
/// global freelist retains the class, and returning to the global freelist
/// releases it.
#[must_use]
pub(crate) struct SizeClassLease {
    token: SizeClassToken,
    class_id: usize,
    thread_cache_capacity: usize,
}

// SAFETY: `SizeClassLease` owns one strong reference to a `SizeClass`, which is
// `Send`.
unsafe impl Send for SizeClassLease {}
// SAFETY: same argument as `Send`, shared access to `SizeClass` is synchronized.
unsafe impl Sync for SizeClassLease {}

impl SizeClassLease {
    /// Retains `class` for a buffer leaving the global freelist.
    #[inline(always)]
    fn retain(class: &SizeClassHandle) -> Self {
        let token = class.token;
        // The route is copied into the lease so buffer return can pick the
        // thread-local cache without dereferencing the class object.
        // SAFETY: the borrowed `class` owns one strong reference for `token`.
        unsafe { token.retain() };
        Self {
            token,
            class_id: class.class_id,
            thread_cache_capacity: class.thread_cache_capacity,
        }
    }

    /// Returns the TLS cache registry id for the owning size class.
    #[inline(always)]
    const fn class_id(&self) -> usize {
        self.class_id
    }

    /// Returns the per-thread cache capacity for the owning size class.
    #[inline(always)]
    const fn thread_cache_capacity(&self) -> usize {
        self.thread_cache_capacity
    }

    /// Returns the referenced size class.
    ///
    /// The token is valid because `SizeClassLease` owns one strong reference.
    #[inline(always)]
    const fn class(&self) -> &SizeClass {
        // SAFETY: guaranteed by the ownership invariant documented on
        // `SizeClassLease`.
        unsafe { self.token.as_ref() }
    }

    /// Returns a buffer to this class's global freelist and releases the class
    /// reference.
    ///
    /// The buffer is parked before the strong reference is released. If this is
    /// the last outstanding reference after the public pool has been dropped,
    /// dropping the `SizeClass` will then drain the just-parked buffer.
    #[inline(always)]
    fn return_global(self, buffer: PooledBuffer) {
        // The lease proves this buffer was checked out from this class's
        // freelist, and checked-out slots are not available in the freelist.
        self.class().global.put(buffer);
        // SAFETY: this lease owns one strong reference.
        unsafe { self.token.release() };
    }

    /// Consumes the lease without releasing its strong reference.
    ///
    /// The returned token still represents one owned strong reference. The
    /// caller takes over responsibility for releasing it. Batch returns use
    /// this to park many buffers first and release their references together
    /// afterwards.
    #[inline(always)]
    const fn into_token(self) -> SizeClassToken {
        self.token
    }
}

/// Free tracked buffer owned by a thread-local size-class cache.
///
/// This is allocator cache state, not a caller-visible pooled view. While an
/// entry is held here, the buffer is owned by the current thread and is not
/// visible to the class-global freelist.
///
/// The buffer's side-table slot identifies the stable slot within its
/// [`SizeClass`] and contains the live lease that keeps that class alive. The
/// entry itself intentionally stores only the buffer so local pop/push does
/// not move separate slot or class metadata per buffer.
struct TlsSizeClassCacheEntry {
    buffer: PooledBuffer,
}

impl TlsSizeClassCacheEntry {
    /// Returns this entry to its class-global freelist.
    #[inline(always)]
    fn return_global(mut self) {
        // SAFETY: local cache entries keep a live lease in the pooled slot.
        let lease = unsafe { self.buffer.take_lease() };
        lease.return_global(self.buffer);
    }
}

/// Per-thread cache for one size class's tracked buffers.
///
/// Each instance is stored in [`TlsSizeClassCaches`] under one global
/// [`SizeClass::class_id`], so all entries in the cache belong to the same size
/// class. The cache owns full [`PooledBuffer`] values while they are local.
/// Interaction with the global freelist happens only on miss refill (take),
/// overflow spill, explicit flush, or thread exit (return).
///
/// When `len > 0`, each initialized entry in `entries[..len]` owns one live
/// slot lease, which keeps the pointed-to class alive. An empty cache owns no
/// class reference. It is only an allocated local stack for a class id.
///
/// The hot steady-state allocation path pops an entry from `entries`, and the
/// hot return path pushes one back while there is room.
struct TlsSizeClassCache {
    entries: Box<[MaybeUninit<TlsSizeClassCacheEntry>]>,
    len: usize,
    capacity: usize,
}

impl TlsSizeClassCache {
    /// Creates a new empty cache with the given maximum thread-cache size.
    fn new(capacity: usize) -> Self {
        let entries = (0..capacity)
            .map(|_| MaybeUninit::uninit())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
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
    /// The returned entry carries a live lease in its pooled slot.
    #[inline(always)]
    fn pop(&mut self, class: &SizeClassHandle) -> Option<TlsSizeClassCacheEntry> {
        if let Some(entry) = self.pop_local() {
            return Some(entry);
        }

        // Take from the class-global freelist on a local miss.
        self.pop_global(class)
    }

    /// Removes and returns one entry from this thread's local stack.
    ///
    /// This touches only thread-local cache state. A returned entry consumes
    /// one live checked-out pooled buffer from this cache.
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
    /// Every claimed global entry gets one retained class reference installed
    /// as a live slot lease. The first claimed entry is returned to the
    /// caller, and additional claimed entries are parked in this cache and
    /// counted by `len`.
    ///
    /// This is separate from [`Self::pop`] so the steady-state allocation hot
    /// path can inline only the local cache hit. We annotate with `inline(never)`
    /// to keep the refill and batching code out of `BufferPoolInner::try_alloc`,
    /// reducing hot-path code size and register pressure.
    #[inline(never)]
    fn pop_global(&mut self, class: &SizeClassHandle) -> Option<TlsSizeClassCacheEntry> {
        // Tiny caches do not batch enough to justify the wider global claim.
        // Keep their miss path equivalent to a single take.
        if self.capacity < MIN_TLS_BATCH_CAPACITY {
            return class
                .take_global()
                .map(|buffer| TlsSizeClassCacheEntry { buffer });
        }

        // Refill larger caches to half capacity. That leaves room for future
        // same-thread returns while still amortizing the global stripe locks
        // over several future local pops.
        let mut entry = None;
        let take = self.capacity / 2;
        class.global.take_batch(take, |buffer| {
            // Each claimed global entry becomes either the returned allocation
            // or a local cache entry, so each needs one retained class
            // reference stored in its slot lease.
            let buffer = class.lease_into(buffer);
            let cache_entry = TlsSizeClassCacheEntry { buffer };
            if entry.is_none() {
                // Hand the first claimed buffer to the allocation that missed
                // locally. Additional claimed buffers refill the local cache.
                entry = Some(cache_entry);
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
    fn push(&mut self, buffer: PooledBuffer) {
        let entry = TlsSizeClassCacheEntry { buffer };

        if self.len < self.capacity {
            // Keep the returned entry local while there is room.
            self.push_local(entry);
            return;
        }

        // Handle overflow when the local stack is full.
        self.push_full(entry);
    }

    /// Pushes one entry onto this thread's local stack.
    ///
    /// The caller must ensure the stack has room.
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
    /// freelist. Larger caches spill the top half of the local stack (the
    /// most recently returned entries, which are contiguous and cheap to
    /// drain without shifting the rest), then keep the incoming entry local
    /// so the dropping thread retains the freshest buffer.
    ///
    /// This is separate from [`Self::push`] so the steady-state return hot path
    /// can inline only the local cache push. We annotate with `inline(never)`
    /// to keep the spill and batching code out of pooled buffer drop when the
    /// local cache has room.
    #[inline(never)]
    fn push_full(&mut self, entry: TlsSizeClassCacheEntry) {
        // Very small caches cannot spill enough entries to amortize a batch
        // insert, so overflow goes straight to the global freelist.
        if self.capacity < MIN_TLS_BATCH_CAPACITY {
            entry.return_global();
            return;
        }

        // Spill half the cache to global to make room.
        let spill = self.len.min(self.capacity / 2).max(1);
        let end = self.len;
        let start = end - spill;
        // Stop tracking slots before moving them out.
        self.len = start;
        self.return_global_batch(start, end);

        // Keep the incoming entry local after making room.
        self.push_local(entry);
    }

    /// Returns the initialized entries in `start..end` to their class-global
    /// freelist as one batch.
    ///
    /// All entries in one cache belong to the same size class, so their slot
    /// leases own strong references represented by one shared token. Each
    /// lease is consumed without being released, then the whole batch parks
    /// under its freelist stripe locks. The strong references are released
    /// only after every buffer is parked. Parking before releasing matters: if
    /// the public pool is already gone and these leases are the last
    /// references, releasing first would drop the freelist before the buffers
    /// returned to it.
    ///
    /// The caller must have already lowered `len` to at most `start`,
    /// transferring ownership of the entries in `start..end` to this function.
    #[inline(never)]
    fn return_global_batch(&mut self, start: usize, end: usize) {
        assert!(start < end && end <= self.capacity);
        assert!(self.len <= start);
        let count = end - start;
        let entries = self.entries.as_mut_ptr();

        // Read the shared token from the first entry's live lease. The
        // not-yet-released lease references keep the class (and its freelist)
        // alive until the releases below.
        // SAFETY: `start..end` was initialized and ownership transferred to
        // this function. The entry is only borrowed here.
        let token = unsafe { (*entries.add(start)).assume_init_ref().buffer.lease() }.token;

        // SAFETY: the lease strong references consumed below are not released
        // until after the batch insert completes.
        let class = unsafe { token.as_ref() };
        let batch = (start..end).map(|index| {
            // SAFETY: `start..end` was initialized before `len` was lowered.
            // Reading moves each entry out and leaves the slot uninitialized.
            let mut entry = unsafe { entries.add(index).read().assume_init() };
            // SAFETY: local cache entries keep a live lease in the pooled
            // slot. The strong reference it owns is intentionally not
            // released here (leases have no drop glue). The token releases
            // below settle it.
            let _ = unsafe { entry.buffer.take_lease() }.into_token();
            entry.buffer
        });
        // Cache entries are distinct checked-out buffers from this class, and
        // the iterator body cannot panic after yielding an entry.
        class.global.put_batch(batch);

        // Release the strong references only now that every buffer is parked.
        for _ in 0..count {
            // SAFETY: each lease consumed above owned one strong reference
            // that has not been released yet.
            unsafe { token.release() };
        }
    }
}

impl Drop for TlsSizeClassCache {
    fn drop(&mut self) {
        if self.len == 0 {
            return;
        }

        // Flush remaining entries (thread exit or explicit flush) with one
        // coalesced batch insert.
        let end = self.len;
        // Stop tracking slots before moving them out.
        self.len = 0;
        self.return_global_batch(0, end);
    }
}

/// Registry of one thread's per-size-class caches.
///
/// A [`super::BufferPool`] keeps its size classes in a vector, so allocation resolves
/// a request to an index within that pool. Thread-local caches need a different
/// key because a thread can use more than one pool. They use the process-global
/// [`SizeClass::class_id`] assigned by [`super::NEXT_SIZE_CLASS_ID`], so index `0` in
/// one pool cannot collide with index `0` in another pool.
///
/// The registry is a sparse vector indexed by `class_id`. Each initialized
/// entry is a [`TlsSizeClassCache`] for that global size class. Missing entries
/// mean this thread has not used that size class yet. Holes can remain for the
/// lifetime of the thread because class ids are monotonic and never reused.
/// Empty initialized caches can also remain after their pool has been dropped.
/// They own no class reference while empty. If the class is still live because
/// a pooled buffer is outstanding, a later return of that buffer to this same
/// thread can use the buffer's live slot lease to make the cache usable
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

    /// Returns the cache for the given class, creating it lazily on first use.
    ///
    /// The caller must provide a live class id from a [`SizeClassHandle`] or
    /// [`SizeClassLease`]. A missing cache starts empty and owns no class
    /// reference. The first local push or global refill stores entries whose
    /// pooled slots contain live leases.
    #[inline(always)]
    fn get_or_init(&mut self, class_id: usize, capacity: usize) -> &mut TlsSizeClassCache {
        // The initialized arm is defensively kept but not reachable today:
        // callers route through this method only when the fast TLS pointer
        // misses, and the fast pointer is published before any cache is
        // created, so an existing cache is always found through the fast path.
        if class_id < self.bins.len() && self.bins[class_id].is_some() {
            return self.bins[class_id]
                .as_mut()
                .expect("class cache was checked as initialized");
        }

        self.init(class_id, capacity)
    }

    /// Initializes and returns the cache for `class_id`.
    ///
    /// This is separate from [`Self::get_or_init`] so the steady-state TLS hit
    /// can inline only the existing-cache lookup. We annotate with
    /// `inline(never)` to keep the resize and allocation path out of pooled
    /// allocation and drop.
    #[inline(never)]
    fn init(&mut self, class_id: usize, capacity: usize) -> &mut TlsSizeClassCache {
        if class_id >= self.bins.len() {
            self.bins.resize_with(class_id + 1, || None);
        }
        self.bins[class_id].get_or_insert_with(|| TlsSizeClassCache::new(capacity))
    }

    /// Returns an initialized cache without creating a missing one.
    #[inline(always)]
    fn get(&mut self, class_id: usize) -> Option<&mut TlsSizeClassCache> {
        self.bins.get_mut(class_id).and_then(Option::as_mut)
    }
}

impl Drop for TlsSizeClassCaches {
    fn drop(&mut self) {
        // The registry lives only in `TLS_SIZE_CLASS_CACHES`' static storage
        // (its const initializer is the sole constructor), and std destroys
        // const-initialized TLS values in place, so a published fast pointer
        // can only refer to this instance. Clear it unconditionally rather
        // than comparing identities: a null fast pointer is always safe (the
        // hot paths fall back to checked TLS access), while a stale one would
        // be a use-after-destroy if std ever moved the value before dropping.
        let this: *mut Self = self;
        BufferPoolThreadCache::TLS_SIZE_CLASS_CACHES_FAST.with(|fast| {
            assert!(fast.get().is_null() || fast.get() == this);
            fast.set(ptr::null_mut());
        });
    }
}

/// Access to the calling thread's local [`BufferPool`](super::BufferPool) caches.
///
/// This type hides the TLS layout used by pooled allocation and return. The
/// main TLS key owns the registry. It has a destructor, so thread exit drops
/// the registry and each `TlsSizeClassCache` flushes its remaining entries to
/// the class-global freelist.
///
/// Steady-state allocation and return first read `TLS_SIZE_CLASS_CACHES_FAST`.
/// If it points at this thread's registry and the requested class cache is
/// initialized, the cache lookup itself touches only thread-local memory:
/// local hits and non-spilling returns complete without shared state, while a
/// local miss refills from the global freelist and a full cache spills to it.
/// Missing TLS state routes through `cache_slow` or `push_slow`, which access
/// the owning TLS key, install the fast pointer, and lazily initialize the
/// class cache.
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
    /// The hot path uses only an already-initialized cache from the fast TLS
    /// pointer. If the fast pointer is missing, or this thread has not
    /// initialized the size class yet, [`Self::push_slow`] performs the checked
    /// TLS access and creates the local cache. The buffer's live slot lease
    /// proves that initialization is safe. During thread-local teardown,
    /// checked TLS access can fail, in that case the buffer falls back to the
    /// global freelist.
    ///
    /// Cache routing reads `class_id` and `thread_cache_capacity` from the
    /// live slot lease (on the slot line the release path has already loaded)
    /// instead of dereferencing the class object, keeping the dependent-load
    /// chain on the return fast path one level shorter.
    #[inline(always)]
    pub(in crate::iobuf) fn push(buffer: PooledBuffer) {
        // SAFETY: pooled buffers entering the pool return path have an
        // initialized live lease.
        let lease = unsafe { buffer.lease() };
        let class_id = lease.class_id();
        let thread_cache_capacity = lease.thread_cache_capacity();
        if thread_cache_capacity == 0 {
            TlsSizeClassCacheEntry { buffer }.return_global();
            return;
        }

        let caches = Self::TLS_SIZE_CLASS_CACHES_FAST.with(|fast| fast.get());
        if !caches.is_null() {
            // SAFETY: the fast pointer is set only from this thread's
            // `TLS_SIZE_CLASS_CACHES` value and cleared before that value
            // drops.
            if let Some(cache) = unsafe { (&mut *caches).get(class_id) } {
                cache.push(buffer);
                return;
            }
        }

        Self::push_slow(buffer);
    }

    /// Returns a buffer to the current thread's local cache after the fast
    /// lookup misses.
    ///
    /// This is called when the fast TLS pointer is not initialized, or when
    /// that pointer exists but this size class has no local cache yet. It
    /// installs the fast TLS pointer after successfully accessing the owning
    /// TLS key, then initializes the size-class cache if needed.
    ///
    /// This is separate from [`Self::push`] so the steady-state return hot path
    /// only contains the initialized-cache lookup and local push.
    #[inline(never)]
    fn push_slow(buffer: PooledBuffer) {
        // SAFETY: pooled buffers entering the pool return path have an
        // initialized live lease.
        let lease = unsafe { buffer.lease() };
        let class_id = lease.class_id();
        let thread_cache_capacity = lease.thread_cache_capacity();
        // Returning a pooled buffer can happen from arbitrary Drop code,
        // including during thread-local destruction. If the local cache is
        // unavailable, fall back to the global freelist instead of panicking.
        match Self::TLS_SIZE_CLASS_CACHES
            .try_with(|caches| {
                let caches = caches.get();

                // Publish the checked owner TLS address to the fast key.
                Self::TLS_SIZE_CLASS_CACHES_FAST.with(|fast| fast.set(caches));

                // SAFETY: this TLS value is only ever accessed by the current thread.
                ptr::NonNull::from(unsafe {
                    (&mut *caches).get_or_init(class_id, thread_cache_capacity)
                })
            })
            .ok()
        {
            Some(mut cache) => {
                // SAFETY: `cache` points to this thread's initialized TLS cache.
                unsafe { cache.as_mut().push(buffer) };
            }
            None => TlsSizeClassCacheEntry { buffer }.return_global(),
        }
    }

    /// Takes a buffer from the current thread's local cache for the given
    /// size class, refilling from the global freelist if the cache is empty.
    ///
    /// The hot path uses only an already-initialized cache from the fast TLS
    /// pointer. On a local miss, the global freelist is queried once. The first
    /// claimed buffer is returned to the caller, and any additional claimed
    /// buffers are appended directly to the local cache.
    #[inline(always)]
    pub(super) fn pop(class: &SizeClassHandle) -> Option<PooledBuffer> {
        if class.thread_cache_capacity == 0 {
            return class.take_global();
        }

        let caches = Self::TLS_SIZE_CLASS_CACHES_FAST.with(|fast| fast.get());
        if !caches.is_null() {
            // SAFETY: the fast pointer is set only from this thread's
            // `TLS_SIZE_CLASS_CACHES` value and cleared before that value
            // drops.
            if let Some(cache) = unsafe { (&mut *caches).get(class.class_id) } {
                return cache.pop(class).map(|entry| entry.buffer);
            }
        }

        // Resolve the cache and fall back to the global freelist if
        // unavailable.
        let Some(mut cache) = Self::cache_slow(class) else {
            return class.take_global();
        };

        // SAFETY: `cache` points to this thread's initialized TLS cache.
        unsafe { cache.as_mut() }
            .pop(class)
            .map(|entry| entry.buffer)
    }

    /// Resolves the local cache after the fast TLS or class-cache lookup
    /// misses.
    ///
    /// This is called when the fast TLS pointer is not initialized, or when
    /// that pointer exists but this size class has no local cache yet. It
    /// installs the fast TLS pointer after successfully accessing the owning
    /// TLS key, then initializes the size-class cache if needed.
    #[inline(never)]
    fn cache_slow(class: &SizeClassHandle) -> Option<ptr::NonNull<TlsSizeClassCache>> {
        // Allocation can happen from caller-owned TLS destructors during thread
        // teardown. Return `None` instead of panicking if the owning TLS key is
        // unavailable.
        Self::TLS_SIZE_CLASS_CACHES
            .try_with(|caches| {
                let caches = caches.get();

                // Publish the checked owner TLS address to the fast key.
                Self::TLS_SIZE_CLASS_CACHES_FAST.with(|fast| fast.set(caches));

                // SAFETY: this TLS value is only ever accessed by the current thread.
                ptr::NonNull::from(unsafe {
                    (&mut *caches).get_or_init(class.class_id, class.thread_cache_capacity)
                })
            })
            .ok()
    }
}

#[cfg(all(test, not(feature = "loom")))]
pub(super) mod tests {
    use super::{
        super::{BufferPool, BufferPoolConfig, NEXT_SIZE_CLASS_ID},
        *,
    };
    use crate::{
        iobuf::{IoBuf, page_size},
        telemetry::metrics::Registry,
    };
    use bytes::BufMut;
    use commonware_utils::{NZU32, NZUsize};
    use std::{
        cell::Cell,
        sync::{Arc, atomic::Ordering, mpsc},
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

    fn get_available(pool: &BufferPool, size: usize) -> i64 {
        let class_index = pool.class_index(size).unwrap();
        let class = &pool.inner.classes[class_index];
        (get_global_len(class) + get_local_len(class)) as i64
    }

    /// Returns the configured per-thread cache capacity.
    pub const fn get_thread_cache_capacity(class: &SizeClass) -> usize {
        class.thread_cache_capacity
    }

    /// Helper to get the number of free buffers parked in the global freelist.
    pub fn get_global_len(class: &SizeClass) -> usize {
        super::super::freelist::tests::len(&class.global)
    }

    /// Helper to get the number of buffers created by the global freelist.
    pub fn get_global_created(class: &SizeClass) -> usize {
        super::super::freelist::tests::created(&class.global)
    }

    /// Returns the number of global freelist stripes for tests.
    pub fn get_global_num_stripes(class: &SizeClass) -> usize {
        super::super::freelist::tests::num_stripes(&class.global)
    }

    /// Helper to get the number of free buffers parked in the current thread's
    /// local cache for a size class.
    pub fn get_local_len(class: &SizeClass) -> usize {
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
    fn test_thread_cache_flush_moves_local_entries_to_global() {
        let page = page_size();
        let pool =
            test_pool(test_config(page, page * 2, 8).with_max_thread_cache_capacity(NZUsize!(4)));

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
        let buffer = class.global.try_create(false).expect("slot reservation");

        // A short global freelist should return the allocation and stop
        // without filling the local cache to its batch target.
        class.global.put(buffer);
        let buffer = BufferPoolThreadCache::pop(&class).expect("global allocation");

        assert_eq!(get_local_len(&class), 0);
        assert_eq!(get_global_len(&class), 0);

        // Return the manually popped entry so the freelist owns and deallocates
        // the buffer at test teardown.
        TlsSizeClassCacheEntry { buffer }.return_global();
    }

    #[test]
    fn test_size_class_leases_use_raw_arc_tokens_across_cache_paths() {
        let class = test_size_class(64, 64);
        let mut cache = TlsSizeClassCache::new(MIN_TLS_BATCH_CAPACITY);
        assert_eq!(size_class_strong_count(&class), 1);

        let mut buffer = class.global.try_create(false).expect("slot reservation");
        let lease = SizeClassLease::retain(&class);
        // SAFETY: this buffer was just created and has no live lease.
        unsafe { buffer.init_lease(lease) };
        assert_eq!(size_class_strong_count(&class), 2);

        // Moving a live pooled buffer into the local cache keeps the same
        // strong reference in the header, it should not clone the class.
        cache.push(buffer);
        assert_eq!(size_class_strong_count(&class), 2);

        let entry = cache.pop(&class).expect("local cache pop");
        assert_eq!(size_class_strong_count(&class), 2);
        entry.return_global();
        assert_eq!(size_class_strong_count(&class), 1);

        for _ in 0..2 {
            let buffer = class.global.try_create(false).expect("slot reservation");
            class.global.put(buffer);
        }

        let entry = cache.pop(&class).expect("global refill");
        assert_eq!(size_class_strong_count(&class), 3);

        entry.return_global();
        assert_eq!(size_class_strong_count(&class), 2);

        // Dropping the cache returns the live refill entry and releases its
        // size-class reference.
        drop(cache);
        assert_eq!(size_class_strong_count(&class), 1);
    }

    #[test]
    fn test_tls_size_class_cache_push_tolerates_empty_spill() {
        let class = test_size_class(64, 64);
        let mut buffer = class.global.try_create(false).expect("slot reservation");
        let lease = SizeClassLease::retain(&class);
        // SAFETY: this buffer was just created and has no live lease.
        unsafe { buffer.init_lease(lease) };
        let mut cache = TlsSizeClassCache::new(0);

        // Small local capacities should bypass batching and push straight to
        // global. The retained reference above is represented by the live
        // slot lease and transferred into `cache.push`.
        cache.push(buffer);
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
        let buffer0 = class.global.try_create(false).expect("first slot");
        let slot0 = buffer0.slot();
        let ptr0 = buffer0.as_ptr();
        let buffer1 = class.global.try_create(false).expect("second slot");
        let slot1 = buffer1.slot();
        let ptr1 = buffer1.as_ptr();
        let mut expected = [(slot0, ptr0), (slot1, ptr1)];
        expected.sort_by_key(|(slot, _)| *slot);

        class.global.put(buffer0);
        class.global.put(buffer1);

        // The freelist does not preserve insertion order, so normalize by slot
        // before asserting identity. The important property is that each slot is
        // returned exactly once with its original parked buffer.
        let mut popped = [
            class.global.take().expect("first pop"),
            class.global.take().expect("second pop"),
        ];
        popped.sort_by_key(PooledBuffer::slot);

        assert_eq!(popped[0].slot(), expected[0].0);
        assert_eq!(popped[0].as_ptr(), expected[0].1);
        assert_eq!(popped[1].slot(), expected[1].0);
        assert_eq!(popped[1].as_ptr(), expected[1].1);

        // Both slots were claimed above, so the global freelist is empty.
        assert!(class.global.take().is_none());

        // Return the buffers so the freelist owns and deallocates them when the
        // test size class is dropped.
        for buffer in popped {
            class.global.put(buffer);
        }
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
    fn test_thread_exit_batch_flush_outlives_pool() {
        // The batch return path (TlsSizeClassCache::drop -> return_global_batch)
        // must park every buffer before releasing the lease references. Drop
        // the pool while a worker's TLS cache holds several entries so the
        // flush's lease releases are the last strong references: the final
        // release drops the SizeClass, whose freelist must reclaim the
        // just-parked buffers.
        let page = page_size();
        let pool = test_pool(test_config(page, page, 8));

        let (cached_tx, cached_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let worker_pool = pool.clone();
        let handle = thread::spawn(move || {
            let class_index = worker_pool
                .class_index(page)
                .expect("class exists for page-sized buffer");
            let class = &worker_pool.inner.classes[class_index];
            assert!(class.thread_cache_capacity >= MIN_TLS_BATCH_CAPACITY);

            // Fill this thread's local cache so the exit flush takes the
            // multi-entry batch path.
            let bufs = (0..MIN_TLS_BATCH_CAPACITY)
                .map(|_| worker_pool.try_alloc(page).expect("tracked allocation"))
                .collect::<Vec<_>>();
            drop(bufs);
            assert_eq!(get_local_len(class), MIN_TLS_BATCH_CAPACITY);

            drop(worker_pool);
            cached_tx.send(()).expect("signal cached buffers");
            release_rx.recv().expect("wait for pool drop");
        });

        cached_rx.recv().expect("worker cached buffers");
        // Every pool handle is gone before the worker exits, so the worker's
        // cached leases are the only remaining size-class references.
        drop(pool);
        release_tx.send(()).expect("release worker");
        handle.join().expect("worker thread should exit cleanly");
    }

    #[test]
    fn test_pooled_ops_inside_tls_destructor_fall_back_to_global() {
        // Pooled operations that run inside another thread_local's destructor
        // may find the pool's TLS registry already destroyed. The push/pop
        // slow paths must then fall back to the global freelist instead of
        // panicking or stranding buffers. Destructor order is
        // platform-dependent, so this test asserts the outcome invariant
        // (a clean exit with every buffer reusable) rather than the path.
        struct ExitReleaser {
            pool: BufferPool,
            size: usize,
            held: Option<IoBuf>,
        }

        impl Drop for ExitReleaser {
            fn drop(&mut self) {
                // An allocation inside a TLS destructor exercises the pop
                // fallback. The drops exercise the push fallback.
                let extra = self
                    .pool
                    .try_alloc(self.size)
                    .expect("pool must serve allocations from TLS destructors");
                drop(extra);
                drop(self.held.take());
            }
        }

        thread_local! {
            static EXIT_RELEASER: Cell<Option<ExitReleaser>> = const { Cell::new(None) };
        }

        let page = page_size();
        let pool = test_pool(test_config(page, page, 4));

        thread::spawn({
            let pool = pool.clone();
            move || {
                // Register the releaser's thread_local before first touching
                // the pool: destructors run in reverse registration order on
                // the platforms we target, so the releaser's pooled operations
                // run after the pool's TLS registry is gone (on platforms with
                // a different order the outcome invariant still holds).
                EXIT_RELEASER.with(|cell| {
                    cell.set(Some(ExitReleaser {
                        pool: pool.clone(),
                        size: page,
                        held: None,
                    }));
                });

                drop(pool.try_alloc(page).expect("first allocation"));
                let mut buf = pool.try_alloc(page).expect("second allocation");
                buf.put_u8(1);
                let held = buf.freeze();
                EXIT_RELEASER.with(|cell| {
                    let mut releaser = cell.take().expect("releaser installed above");
                    releaser.held = Some(held);
                    cell.set(Some(releaser));
                });
            }
        })
        .join()
        .expect("worker thread must exit cleanly");

        // Nothing may remain in the dead thread's cache, and every buffer the
        // worker touched must be reusable: with a class capacity of four, all
        // four allocations succeed only if none were stranded.
        let class_index = pool
            .class_index(page)
            .expect("class exists for page-sized buffer");
        assert_eq!(get_local_len(&pool.inner.classes[class_index]), 0);
        let bufs = (0..4)
            .map(|i| {
                pool.try_alloc(page)
                    .unwrap_or_else(|_| panic!("buffer {i} was stranded at thread exit"))
            })
            .collect::<Vec<_>>();
        drop(bufs);
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
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use commonware_utils::{NZU32, NZUsize};
    use loom::thread;

    // Models the multi-entry TLS teardown edge without using OS thread-local
    // state, which loom cannot reset between model executions. Dropping the
    // production cache takes each real pooled-slot lease, batch-parks both
    // slots, and only then releases the lease references. The final class-handle
    // release races that batch return, so either side may perform the final
    // SizeClass drop and reclaim the parked buffers.
    #[test]
    fn tls_batch_drop_races_pool_teardown() {
        loom::model(|| {
            let class = SizeClassHandle::new(1, 64, 64, NZU32!(2), NZUsize!(1), 2, false);
            let mut cache = TlsSizeClassCache::new(2);

            for _ in 0..2 {
                let buffer = class.try_create(false).expect("tracked slot");
                cache.push(buffer);
            }
            assert_eq!(cache.len, 2);

            let t = thread::spawn(move || drop(cache));
            drop(class);
            t.join().unwrap();
        });
    }
}
