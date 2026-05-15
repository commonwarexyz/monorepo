//! Striped global freelist for one buffer-pool size class.
//!
//! A [`Freelist`] owns the allocation layout for one [`super::pool::BufferPool`]
//! size class and is responsible for deallocating every tracked buffer created
//! with that layout. Buffers that are not owned by pooled views and not held in
//! a thread-local cache are parked in the freelist, making them available for
//! reuse by any thread in the pool. Each tracked buffer has a stable slot id
//! within its size class.
//!
//! A [`PooledBuffer`] does not carry its allocation layout. Any buffer created
//! by this freelist, or taken from it, must eventually be returned to the same
//! freelist before the freelist is finally dropped. [`Freelist::drain`] and
//! [`Drop`] only release buffers currently parked here. **An outstanding buffer
//! that is never returned will leak**.
//!
//! The buffer pool keeps this requirement by pairing every pooled backing
//! outside the freelist with a size-class lease, and by banking one strong
//! size-class reference for every buffer held in a thread-local cache. Those
//! leases and banked references keep the owning size class, and therefore this
//! freelist, alive until the buffer returns here.
//!
//! This is intentionally narrower than a general multi-producer, multi-consumer
//! queue:
//!
//! - Capacity is fixed when the size class is created.
//! - Callers only need to take any free slot, not preserve order.
//! - Slot ownership is managed by the buffer pool.
//! - Refill and spill paths naturally move buffers in batches.
//!
//! Each slot has two pieces of freelist state: a parking cell and a free bit.
//! The parking cell holds the [`PooledBuffer`] while the slot is globally free.
//! The bit records whether that cell currently contains an initialized buffer
//! that can be taken. The bit transition is the synchronization boundary:
//! returning a buffer writes the cell and then sets the bit, while taking a
//! buffer clears a set bit and then reads the cell.
//!
//! Free bits are split across cache-line-padded atomic words. The pool passes
//! its expected parallelism so the freelist can size this bitmap for the
//! expected contention level. The freelist rounds that target up to a power of
//! two, caps it so every word can contain at least one slot, and grows it when
//! needed so no bitmap word tracks more than 64 slots.
//!
//! Consecutive slot ids are not packed into the same word. Instead low slot-id
//! bits choose the word and high slot-id bits choose the bit inside that word.
//! With a power-of-two word count, the mapping is:
//!
//! - `word_mask = word_count - 1`
//! - `word_shift = log2(word_count)`
//! - `word_index = slot & word_mask`
//! - `bit_index = slot >> word_shift`
//! - `bit_mask = 1 << bit_index`
//!
//! For an eight-word freelist, slots are arranged like this:
//!
//! ```text
//!            word 0   word 1   word 2   word 3   word 4   word 5   word 6   word 7
//! bit 0:     slot 0   slot 1   slot 2   slot 3   slot 4   slot 5   slot 6   slot 7
//! bit 1:     slot 8   slot 9   slot 10  slot 11  slot 12  slot 13  slot 14  slot 15
//! bit 2:     slot 16  slot 17  slot 18  slot 19  slot 20  slot 21  slot 22  slot 23
//! ...
//! ```
//!
//! This gives concurrent threads more independent atomic words to target
//! without changing the slot ids handed back to the pool.
//!
//! Each thread also gets a stable probe id. The probe id uses the same
//! power-of-two split as slot ids:
//!
//! - low id bits choose the thread's home word
//! - higher id bits identify the home-word collision group
//! - the low six bits of that group are reversed to choose the starting bit
//!
//! The first `word_count` long-lived workers therefore start on different
//! bitmap words. Workers that already start on different words do not need
//! distinct bit offsets. When more workers share the same home word, their bit
//! offsets spread by halves, quarters, and so on.
//!
//! ```text
//! word_count = 8
//!
//! thread id:       0  1  2  3  4  5  6  7 |  8  9 10 11 12 13 14 15
//! home word:       0  1  2  3  4  5  6  7 |  0  1  2  3  4  5  6  7
//! group:           0  0  0  0  0  0  0  0 |  1  1  1  1  1  1  1  1
//! bit offset:      0  0  0  0  0  0  0  0 | 32 32 32 32 32 32 32 32
//!
//! home_word = thread_id & word_mask
//! group     = thread_id >> word_shift
//! offset    = reverse_low_6(group)
//!
//! home-word collision sequence:
//!
//! thread id:   0   8  16  24  32  40  48  56
//! group:       0   1   2   3   4   5   6   7
//! bit offset:  0  32  16  48   8  40  24  56
//! ```
//!
//! The hot paths are fast for a few concrete reasons:
//!
//! - `put` is just "write buffer into the parking cell, then `fetch_or` one bit".
//! - `take` uses a stable per-thread home word before scanning others, so
//!   threads tend to start from different stripes.
//! - `take` and `take_batch` rotate bit selection inside each word, so threads
//!   that share a word do not all probe bit 0 first.
//! - `take` claims bits with `fetch_and` instead of a compare-and-swap loop.
//!   Two threads removing different bits from the same word can both succeed
//!   without one having to restart from scratch.
//! - `put_batch` coalesces returned slots per word, turning many logical
//!   inserts into one atomic `fetch_or` per touched stripe.
//! - `take_batch` claims several bits from one word with one atomic operation,
//!   which matches the refill behavior of the thread-local caches.
//!
//! The shared bitmap operations are lock-free, but the structure is not a
//! standalone general-purpose container. It relies on the buffer pool's
//! ownership discipline: a slot is either owned by a pooled backing, parked in a
//! thread-local cache, or available in this freelist. Only the thread that owns
//! a slot outside the freelist may access that slot's parking cell.
use super::buffer::PooledBuffer;
use crossbeam_utils::CachePadded;
use std::{
    alloc::Layout,
    cell::Cell,
    mem::MaybeUninit,
    num::{NonZeroU32, NonZeroUsize},
    sync::atomic::Ordering,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::{
            cell::UnsafeCell,
            sync::atomic::{AtomicU64, AtomicUsize},
        };
    } else {
        use std::{
            cell::UnsafeCell,
            sync::atomic::{AtomicU64, AtomicUsize},
        };
    }
}

/// Number of slot bits tracked in each bitmap word.
const SLOT_BITMAP_WORD_BITS: usize = u64::BITS as usize;
/// Number of low-order bits needed to address bits within one bitmap word.
const SLOT_BITMAP_WORD_SHIFT: u32 = SLOT_BITMAP_WORD_BITS.trailing_zeros();
/// Number of word masks stored on the stack before falling back to heap scratch.
const INLINE_PUT_BATCH_MASKS: usize = 128;

/// Bounded lock-free freelist of tracked buffers for one size class.
///
/// The freelist owns the [`Layout`] shared by every tracked buffer in the size
/// class. Pooled backing values and thread-local caches may temporarily hold
/// [`PooledBuffer`] handles, but those handles must eventually return here so
/// they can be released with the correct layout. The buffer pool keeps the
/// freelist alive for those outstanding handles with pooled-backing leases
/// or TLS-banked size-class references. Draining or dropping the freelist
/// only deallocates buffers currently parked in it.
///
/// The bitmap is intentionally striped over a power-of-two number of words.
/// That makes the slot-to-word mapping cheap and keeps small freelists from
/// degenerating into a single hot atomic word.
pub struct Freelist {
    /// Allocation layout shared by every tracked buffer.
    layout: Layout,
    /// Number of slot ids reserved for created buffers.
    ///
    /// This is a monotonic high-water mark for slot assignment. Draining
    /// globally-free buffers does not decrement it because higher slot ids may
    /// still be owned by a pooled backing or parked in thread-local caches.
    created: AtomicUsize,
    /// Cache-line-padded striped bitmap of free slots.
    ///
    /// Padding matters here because threads often target different words in
    /// steady state. Without padding, different bitmap words could still share
    /// a cache line even when they represent disjoint slot stripes.
    words: Box<[CachePadded<AtomicU64>]>,
    /// Per-slot parking place for returned buffers.
    ///
    /// A bit transition is the synchronization boundary. `put` writes the
    /// buffer into the parking cell before setting the bit, and `take` clears
    /// the bit before reading the buffer back out.
    storage: Box<[UnsafeCell<MaybeUninit<PooledBuffer>>]>,
    /// Mask used to map a slot id to its striped bitmap word.
    word_mask: usize,
    /// Number of low slot-id bits consumed by the word index.
    word_shift: u32,
}

// SAFETY: parking cells are only accessed by the thread that currently
// owns their slot id. Publication and removal from the global free set are
// synchronized via bitmap bit transitions.
unsafe impl Send for Freelist {}
// SAFETY: Same slot-ownership and bit-transition synchronization as above.
unsafe impl Sync for Freelist {}

impl Freelist {
    /// Creates a new fixed-capacity freelist.
    ///
    /// `parallelism` is the expected number of threads contending for the
    /// freelist. The actual word count is rounded to a power of two and capped
    /// so every word can contain at least one slot.
    ///
    /// If `prefill` is true, creates `capacity` buffers and makes them
    /// immediately available in the freelist.
    pub fn new(
        capacity: NonZeroU32,
        parallelism: NonZeroUsize,
        layout: Layout,
        prefill: bool,
    ) -> Self {
        assert!(layout.size() > 0, "layout size must be non-zero");
        let capacity = capacity.get() as usize;

        // Keep the caller-facing knob as expected parallelism, then derive an
        // implementation-friendly stripe count here. Capping at capacity avoids
        // permanently empty stripes when a small pool is used with a large
        // parallelism setting.
        let max_stripes = 1usize << capacity.ilog2();
        let target_stripes = parallelism
            .get()
            .checked_next_power_of_two()
            .unwrap_or(max_stripes)
            .min(max_stripes);

        // Small freelists reserve the target number of striped words when
        // capacity allows it, so different threads can start from different
        // cache lines. Large freelists are constrained by the number of bits
        // required to represent all slots.
        let word_count = target_stripes
            .max(capacity.div_ceil(SLOT_BITMAP_WORD_BITS))
            .next_power_of_two();
        // `word_count` is always a power of two, so slot mapping can use the
        // low bits as a word index and the remaining high bits as the bit
        // index inside that word.
        let word_shift = word_count.trailing_zeros();
        let word_mask = word_count - 1;

        let words = (0..word_count)
            .map(|_| CachePadded::new(AtomicU64::new(0)))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let storage = (0..capacity)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        let freelist = Self {
            layout,
            created: AtomicUsize::new(0),
            words,
            storage,
            word_mask,
            word_shift,
        };

        if prefill {
            freelist.put_batch((0..capacity).map(|_| {
                freelist
                    .try_create(false)
                    .expect("prefill creates exactly capacity buffers")
            }));
        }

        freelist
    }

    /// Creates a new buffer and reserves a stable slot id for it.
    ///
    /// Returns `None` once every slot id in the fixed-capacity freelist has
    /// been reserved.
    ///
    /// The returned buffer does not deallocate itself. The `(slot, buffer)`
    /// pair must be returned to this same freelist before the freelist is
    /// finally dropped, otherwise the buffer leaks.
    #[inline(always)]
    pub(super) fn try_create(&self, zeroed: bool) -> Option<(u32, PooledBuffer)> {
        let slot = self
            .created
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |created| {
                (created < self.storage.len()).then_some(created + 1)
            })
            .ok()? as u32;

        let buffer = if zeroed {
            PooledBuffer::new_zeroed(self.layout)
        } else {
            PooledBuffer::new(self.layout)
        };

        Some((slot, buffer))
    }

    /// Returns the bitmap word index and bit mask for a slot id.
    ///
    /// Low slot-id bits choose the cache-line-padded word. High slot-id bits
    /// choose the bit inside that word, spreading consecutive slots across
    /// stripes instead of packing them into one atomic word.
    #[inline(always)]
    const fn slot_word(&self, slot: u32) -> (usize, u64) {
        let slot = slot as usize;
        let word_index = slot & self.word_mask;
        let bit = slot >> self.word_shift;
        (word_index, 1u64 << bit)
    }

    /// Returns the slot id represented by a bitmap word index and bit index.
    ///
    /// This is the inverse of [`Self::slot_word`] and is used after a bit has
    /// been claimed from the bitmap.
    #[inline(always)]
    const fn slot_index(&self, word_index: usize, bit: usize) -> u32 {
        let slot = (bit << self.word_shift) | word_index;
        slot as u32
    }

    /// Puts one tracked buffer into the global freelist.
    ///
    /// The buffer is first written back into its parking cell, then the slot's
    /// free bit is set with `Release` ordering. A successful `take` performs
    /// the matching `Acquire` operation before reading the buffer back out.
    ///
    /// The caller must own `slot`, and `slot` must not already be available in
    /// this freelist. `buffer` must belong to this freelist, it must have been
    /// allocated by this freelist.
    #[inline]
    pub fn put(&self, slot: u32, buffer: PooledBuffer) {
        // Park the buffer before marking the slot free.
        self.park(slot, buffer);

        // Setting the slot bit makes the parked buffer available. `Release` pairs
        // with the taker's `Acquire` clear before it reads the parking cell.
        let (word_index, mask) = self.slot_word(slot);
        let previous = self.words[word_index].fetch_or(mask, Ordering::Release);
        assert_eq!(
            previous & mask,
            0,
            "returned slot must not already be marked free"
        );
    }

    /// Puts several tracked buffers into the global freelist.
    ///
    /// Batch insertion groups returned slots by bitmap word so each touched
    /// stripe needs only one atomic `fetch_or`, regardless of how many entries
    /// in the batch map to that word.
    ///
    /// The caller must own every slot in the batch. Slots must be unique within
    /// the batch and must not already be available in this freelist. Each
    /// buffer must belong to this freelist.
    ///
    /// The iterator **must not panic** after yielding an entry.
    ///
    /// `BufferPool` callers use simple drain and array iterators, avoiding
    /// per-entry guards keeps this path allocation-free for ordinary batches.
    #[inline]
    pub fn put_batch(&self, entries: impl IntoIterator<Item = (u32, PooledBuffer)>) {
        let mut entries = entries.into_iter();

        // Keep empty and single-entry batches on the cheapest path. The mask
        // scratch space is only needed once there are multiple slots to
        // coalesce.
        let Some((slot, buffer)) = entries.next() else {
            return;
        };
        let Some((next_slot, next_buffer)) = entries.next() else {
            self.put(slot, buffer);
            return;
        };

        let word_count = self.words.len();
        if word_count <= INLINE_PUT_BATCH_MASKS {
            let mut masks = MaybeUninit::<[u64; INLINE_PUT_BATCH_MASKS]>::uninit();
            // Only the active bitmap words need scratch space. Avoid clearing
            // the whole inline array for small freelists.
            //
            // SAFETY: `word_count <= INLINE_PUT_BATCH_MASKS`, so the
            // initialized prefix is in bounds. `u64` has no drop glue, and the
            // uninitialized tail is never exposed.
            let masks = unsafe {
                let ptr = masks.as_mut_ptr().cast::<u64>();
                ptr.write_bytes(0, word_count);
                std::slice::from_raw_parts_mut(ptr, word_count)
            };
            self.put_entries(masks, slot, buffer, next_slot, next_buffer, entries);
        } else {
            // Very large freelists are uncommon, so keep the common case on the
            // stack and fall back to heap scratch only when the bitmap is wider
            // than the fixed inline staging area.
            let mut masks = vec![0u64; word_count];
            self.put_entries(
                masks.as_mut_slice(),
                slot,
                buffer,
                next_slot,
                next_buffer,
                entries,
            );
        }
    }

    /// Inserts a multi-entry batch using per-word scratch masks.
    ///
    /// `put_batch` peels the first two entries before calling this helper, so
    /// this path only handles batches large enough to benefit from coalescing.
    /// `masks` must contain exactly one zeroed entry per bitmap word. Each slot
    /// is parked first and ORed into its word's scratch mask. Once all entries
    /// are staged, one `Release` `fetch_or` per non-empty mask makes the
    /// corresponding parked buffers available.
    ///
    /// The caller must own every slot, slots must be unique, none of the slots
    /// may already be available in this freelist, and every buffer must belong
    /// to this freelist. The iterator must not panic after yielding an entry,
    /// because staged-but-not-inserted buffers would no longer be owned by the
    /// caller and would not yet be reachable through the bitmap.
    #[inline(always)]
    fn put_entries(
        &self,
        masks: &mut [u64],
        slot: u32,
        buffer: PooledBuffer,
        next_slot: u32,
        next_buffer: PooledBuffer,
        entries: impl Iterator<Item = (u32, PooledBuffer)>,
    ) {
        // Masks are staged by word after parking the buffers. The later
        // Release `fetch_or` makes every staged slot in that word available.
        self.stage_put(masks, slot, buffer);
        self.stage_put(masks, next_slot, next_buffer);
        for (slot, buffer) in entries {
            self.stage_put(masks, slot, buffer);
        }

        for (word_index, &mask) in masks.iter().enumerate() {
            if mask == 0 {
                continue;
            }

            // One Release operation makes every parked buffer represented
            // by this word mask.
            let previous = self.words[word_index].fetch_or(mask, Ordering::Release);
            assert_eq!(
                previous & mask,
                0,
                "returned slot batch must not already contain a free slot"
            );
        }
    }

    /// Parks one buffer and records its slot in the batch scratch mask.
    ///
    /// This helper intentionally does not touch the atomic bitmap. The caller
    /// later inserts the accumulated mask for each word, so multiple slots that
    /// map to the same bitmap word share a single `Release` operation. Parking
    /// happens before the bit is staged, preserving the same order as `put`.
    ///
    /// `masks` must contain the scratch word for `slot`.
    #[inline(always)]
    fn stage_put(&self, masks: &mut [u64], slot: u32, buffer: PooledBuffer) {
        // Park first, then stage the bit for the later per-word insert.
        self.park(slot, buffer);
        let (word_index, mask) = self.slot_word(slot);
        masks[word_index] |= mask;
    }

    /// Takes any one available slot from the global freelist.
    ///
    /// On success, ownership of the returned `(slot, buffer)` pair is
    /// transferred to the caller. The pair must be returned to this same
    /// freelist before the freelist is finally dropped, otherwise the buffer
    /// leaks.
    ///
    /// The search starts from a stable per-thread home word and scans the other
    /// stripes only on miss. Within a word, `fetch_and` claims one bit. That is
    /// important: unlike a full-word CAS loop, two threads removing different
    /// bits from the same word can both succeed.
    #[inline]
    pub fn take(&self) -> Option<(u32, PooledBuffer)> {
        // Capture this thread's probe state once so the inner loop does not
        // repeatedly touch thread-local storage.
        let probe = SlotBitmapProbe::new(self.word_mask, self.word_shift);

        for scanned in 0..self.words.len() {
            let word_index = probe.word_index(scanned);
            let word_ref = &self.words[word_index];
            // This relaxed load only chooses candidate bits. The Acquire
            // `fetch_and` below claims the bit if it is still present.
            let mut word = word_ref.load(Ordering::Relaxed);

            while word != 0 {
                // Probe a thread-specific bit order inside the chosen word so
                // colliding threads do not all stampede bit 0 first.
                let bit = probe.select_set_bit(word);
                let mask = 1u64 << bit;
                let observed = word_ref.fetch_and(!mask, Ordering::Acquire);
                if observed & mask != 0 {
                    let slot = self.slot_index(word_index, bit);
                    // Clear the bit before reading the parked buffer. The
                    // Acquire `fetch_and` above synchronizes with the put-side
                    // Release operation.
                    return Some((slot, self.unpark(slot)));
                }

                // Another thread removed that bit first. Reuse the returned
                // word value instead of restarting the whole scan from the
                // beginning.
                word = observed & !mask;
            }
        }

        None
    }

    /// Takes up to `max` available slots from the global freelist.
    ///
    /// Ownership of each claimed `(slot, buffer)` pair is transferred to
    /// `on_entry`. Each pair must be returned to this same freelist before the
    /// freelist is finally dropped, otherwise the buffer leaks.
    ///
    /// `on_entry` receives each claimed `(slot, buffer)` pair. This avoids
    /// internal allocation and lets callers fill an existing spill/refill
    /// buffer directly. `on_entry` **must not panic**: for batch claims, bits
    /// are cleared before buffers are handed to the callback, so a panic could
    /// strand already-claimed slots outside the freelist.
    ///
    /// For `max > 1`, the implementation tries to claim several bits from the
    /// same word in a single atomic `fetch_and`, which amortizes the shared
    /// synchronization cost across the batch.
    #[inline]
    pub fn take_batch(&self, max: usize, mut on_entry: impl FnMut(u32, PooledBuffer)) -> usize {
        if max == 1 {
            // Keep single-slot takes on the cheaper path.
            let Some((slot, buffer)) = self.take() else {
                return 0;
            };
            on_entry(slot, buffer);
            return 1;
        }

        // Capture this thread's probe state once so the inner loop does not
        // repeatedly touch thread-local storage.
        let probe = SlotBitmapProbe::new(self.word_mask, self.word_shift);
        let mut filled = 0;

        for scanned in 0..self.words.len() {
            if filled == max {
                break;
            }

            let word_index = probe.word_index(scanned);
            let word_ref = &self.words[word_index];
            // This relaxed load only chooses candidate bits. The Acquire
            // `fetch_and` below claims whichever candidates are still present.
            let mut word = word_ref.load(Ordering::Relaxed);

            while word != 0 && filled < max {
                // Stage several candidate bits from the current word, then try
                // to clear all of them with one atomic operation.
                let claim = probe.select_set_bits(word, max - filled);
                let observed = word_ref.fetch_and(!claim, Ordering::Acquire);
                // `claim` is speculative. Intersect it with the observed word
                // to keep only the bits this thread actually cleared.
                let mut claimed = observed & claim;

                while claimed != 0 {
                    let bit = claimed.trailing_zeros() as usize;
                    let slot = self.slot_index(word_index, bit);
                    // These bits were cleared by the Acquire `fetch_and` above,
                    // so each corresponding parked buffer is now owned by this
                    // caller.
                    on_entry(slot, self.unpark(slot));
                    claimed &= claimed - 1;
                    filled += 1;
                }

                // Continue from the word snapshot returned by `fetch_and`.
                word = observed & !claim;
            }
        }

        filled
    }

    /// Drops every currently available buffer from the global freelist.
    ///
    /// This is a teardown operation. Drained slot ids are not made available for
    /// new creations. Buffers currently owned by a pooled backing or parked in
    /// thread-local caches are not visible to this method and remain the
    /// responsibility of their current owner until they are returned.
    ///
    /// Returns the number of drained slots.
    #[inline]
    pub fn drain(&self) -> usize {
        let mut drained = 0;

        for (word_index, word) in self.words.iter().enumerate() {
            // Drain clears each whole word directly instead of using the
            // probe-based take path. That keeps destruction independent from
            // thread-local probe state, which may already be unavailable while
            // TLS caches are being destroyed.
            let mut claimed = word.swap(0, Ordering::Acquire);

            while claimed != 0 {
                let bit = claimed.trailing_zeros() as usize;
                let slot = self.slot_index(word_index, bit);
                let buffer = self.unpark(slot);
                // SAFETY: every buffer inserted into this freelist must have been
                // allocated with this freelist's layout.
                unsafe { buffer.deallocate(self.layout) };
                claimed &= claimed - 1;
                drained += 1;
            }
        }

        drained
    }

    /// Parks a buffer in the storage cell for a slot outside the freelist.
    ///
    /// The caller must own `slot` and mark the corresponding bit only after
    /// this write completes.
    #[inline(always)]
    fn park(&self, slot: u32, buffer: PooledBuffer) {
        let cell = self
            .storage
            .get(slot as usize)
            .expect("slot id must refer to an allocated slot");

        cfg_if::cfg_if! {
            if #[cfg(not(feature = "loom"))] {
                // SAFETY: the caller owns this slot while it is outside the
                // freelist, so no other thread can access the parking cell until
                // the slot bit is set.
                unsafe {
                    (*cell.get()).write(buffer);
                }
            } else {
                // Use loom's tracked cell API so the model can detect a
                // parking-cell access that is not synchronized by the bitmap bit
                // transition.
                cell.with_mut(|ptr| {
                    // SAFETY: the caller owns this slot while it is outside the
                    // freelist, so no other thread can access the parking cell
                    // until the slot bit is set.
                    unsafe { (*ptr).write(buffer) };
                });
            }
        }
    }

    /// Removes the parked buffer from a slot whose free bit was just claimed.
    ///
    /// The caller must have cleared the slot's bit before reading the cell.
    #[inline(always)]
    fn unpark(&self, slot: u32) -> PooledBuffer {
        let cell = self
            .storage
            .get(slot as usize)
            .expect("slot id must refer to an allocated slot");

        cfg_if::cfg_if! {
            if #[cfg(not(feature = "loom"))] {
                // SAFETY: a successful bit clear removes this slot from the free
                // set, so we have exclusive access to the initialized buffer that
                // was made available by the matching put.
                unsafe { (*cell.get()).assume_init_read() }
            } else {
                // Use loom's tracked cell API so the model can detect a
                // parking-cell access that is not synchronized by the bitmap bit
                // transition.
                cell.with_mut(|ptr| {
                    // SAFETY: a successful bit clear removes this slot from the
                    // free set, so we have exclusive access to the initialized
                    // buffer that was made available by the matching put.
                    unsafe { (*ptr).assume_init_read() }
                })
            }
        }
    }
}

impl Drop for Freelist {
    fn drop(&mut self) {
        // Any slot still free in the freelist owns an initialized parked
        // buffer in its parking cell. Drain them explicitly so the underlying
        // pooled allocations are released before the raw storage backing the
        // freelist itself goes away.
        self.drain();
    }
}

/// Per-call probe state for choosing bitmap words and bits.
///
/// Keeping this logic in one place makes the claim path easier to read and
/// keeps the freelist API focused on putting and taking slots.
struct SlotBitmapProbe {
    start_word: usize,
    word_mask: usize,
    bit_offset: u32,
}

// Monotonic source for per-thread probe ids.
cfg_if::cfg_if! {
    if #[cfg(not(feature = "loom"))] {
        static NEXT_SLOT_BITMAP_THREAD_ID: AtomicUsize = AtomicUsize::new(0);
    } else {
        loom::lazy_static! {
            // Loom's `AtomicUsize::new` is not const, so the modeled global
            // counter has to be initialized through `lazy_static!`.
            static ref NEXT_SLOT_BITMAP_THREAD_ID: AtomicUsize = AtomicUsize::new(0);
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(feature = "loom"))] {
        thread_local! {
            // The per-thread probe id gives each thread a stable starting point for
            // bitmap scans.
            //
            // Keep this const-initialized so the TLS value has no destructor. The
            // cold path initializes the id explicitly instead of using a lazy TLS
            // initializer.
            static TLS_SLOT_BITMAP_THREAD_ID: Cell<Option<usize>> = const { Cell::new(None) };
        }
    } else {
        loom::thread_local! {
            // Loom's `thread_local!` macro does not accept const initializers.
            static TLS_SLOT_BITMAP_THREAD_ID: Cell<Option<usize>> = Cell::new(None);
        }
    }
}

impl SlotBitmapProbe {
    /// Builds probe state for the current thread and freelist layout.
    ///
    /// The thread's stable id chooses both its home word and its preferred bit
    /// offset inside each word.
    #[inline(always)]
    fn new(word_mask: usize, word_shift: u32) -> Self {
        let thread_id = TLS_SLOT_BITMAP_THREAD_ID.with(|thread_id| {
            if let Some(id) = thread_id.get() {
                return id;
            }

            // Relaxed ordering is enough because probe ids only spread starting
            // points across bitmap words, they do not synchronize buffer
            // ownership.
            let id = NEXT_SLOT_BITMAP_THREAD_ID.fetch_add(1, Ordering::Relaxed);
            thread_id.set(Some(id));
            id
        });

        Self {
            // Low id bits choose the first bitmap word this thread probes.
            // With a power-of-two word count, masking is equivalent to modulo
            // but avoids a division on the hot path.
            start_word: thread_id & word_mask,
            word_mask,
            // Threads that share a home word should start from well-separated
            // bits within that word.
            bit_offset: Self::bit_offset(thread_id, word_shift),
        }
    }

    /// Returns the bit offset for this thread's home-word collision group.
    #[inline(always)]
    const fn bit_offset(thread_id: usize, word_shift: u32) -> u32 {
        // `word_shift` is `log2(word_count)`, so shifting drops the id bits
        // used to choose the home word. Bit-reversing the low six group bits
        // gives offsets `0, 32, 16, 48, ...`, spreading home-word collisions
        // across the 64-bit word for power-of-two batch sizes.
        let group = thread_id >> word_shift;
        (group.reverse_bits() >> (usize::BITS - SLOT_BITMAP_WORD_SHIFT)) as u32
    }

    /// Returns the word index to inspect after `scanned` words.
    #[inline(always)]
    const fn word_index(&self, scanned: usize) -> usize {
        (self.start_word + scanned) & self.word_mask
    }

    /// Selects one set bit from `word` using a rotated probe order.
    ///
    /// This probe's bit offset becomes the first position checked. The returned
    /// index is in the original, unrotated word.
    #[inline(always)]
    const fn select_set_bit(&self, word: u64) -> usize {
        // Rotate the word so the thread's preferred probe offset becomes bit 0,
        // select the first set bit in that rotated view, then rotate the answer
        // back into the original word numbering.
        let rotated = word.rotate_right(self.bit_offset);
        ((rotated.trailing_zeros() + self.bit_offset) & (SLOT_BITMAP_WORD_BITS as u32 - 1)) as usize
    }

    /// Selects up to `limit` set bits from `word` using a rotated probe order.
    ///
    /// The returned mask is in the original, unrotated word and can be used
    /// directly in a `fetch_and`.
    #[inline]
    const fn select_set_bits(&self, word: u64, limit: usize) -> u64 {
        // Gather up to `limit` set bits using the same rotated probe order as
        // `select_set_bit`. The result is rotated back so callers can apply it
        // directly as a mask against the original word.
        let mut remaining = word.rotate_right(self.bit_offset);
        let mut selected = 0u64;
        let mut taken = 0;

        while remaining != 0 && taken < limit {
            let bit = remaining.trailing_zeros();
            let mask = 1u64 << bit;
            selected |= mask;
            remaining &= !mask;
            taken += 1;
        }

        selected.rotate_left(self.bit_offset)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use commonware_utils::{NZUsize, NZU32};
    use std::sync::{
        atomic::{AtomicUsize as StdAtomicUsize, Ordering as AtomicOrdering},
        Arc, Barrier,
    };

    pub fn created(freelist: &Freelist) -> usize {
        freelist.created.load(Ordering::Relaxed)
    }

    pub fn len(freelist: &Freelist) -> usize {
        freelist
            .words
            .iter()
            .map(|word| word.load(Ordering::Acquire).count_ones() as usize)
            .sum()
    }

    pub fn num_words(freelist: &Freelist) -> usize {
        freelist.words.len()
    }

    const TEST_LAYOUT: Layout = match Layout::from_size_align(64, 64) {
        Ok(layout) => layout,
        Err(_) => unreachable!(),
    };

    #[test]
    fn test_freelist_try_create_tracks_capacity_and_prefill() {
        let set = Freelist::new(NZU32!(2), NZUsize!(1), TEST_LAYOUT, false);
        assert_eq!(created(&set), 0);

        // Without prefill, slots are reserved lazily as buffers are created.
        let (slot0, buffer0) = set.try_create(false).expect("first creation");
        let (slot1, buffer1) = set.try_create(false).expect("second creation");
        assert_eq!(slot0, 0);
        assert_eq!(slot1, 1);
        assert_eq!(created(&set), 2);

        // Slot reservation is bounded by capacity, even if the created
        // buffers have not yet been returned to the freelist.
        assert!(set.try_create(false).is_none());

        // Returning created buffers makes them available for reuse, but does
        // not reopen slot creation beyond the fixed capacity.
        set.put(slot0, buffer0);
        set.put(slot1, buffer1);
        assert_eq!(len(&set), 2);

        assert_eq!(created(&set), 2);
        assert!(set.try_create(false).is_none());

        // Prefill reserves and publishes every slot during construction.
        let prefilled = Freelist::new(NZU32!(2), NZUsize!(1), TEST_LAYOUT, true);
        assert_eq!(created(&prefilled), 2);
        assert_eq!(len(&prefilled), 2);
    }

    #[test]
    fn test_freelist_returns_each_slot_once() {
        // Use a non-power-of-two capacity to cover partial final words while
        // keeping the expected slot set easy to inspect.
        let set = Freelist::new(NZU32!(3), NZUsize!(1), TEST_LAYOUT, false);

        let (slot0, buffer0) = set.try_create(false).unwrap();
        let (slot1, buffer1) = set.try_create(false).unwrap();
        let (slot2, buffer2) = set.try_create(false).unwrap();
        assert_eq!([slot0, slot1, slot2], [0, 1, 2]);
        set.put(slot0, buffer0);
        set.put(slot1, buffer1);
        set.put(slot2, buffer2);

        // Every free slot should be returned exactly once, and the
        // freelist should report empty afterward.
        let mut seen = [false; 3];
        let mut taken = Vec::new();
        for _ in 0..3 {
            let (slot, buffer) = set.take().expect("slot should be available");
            assert!(!seen[slot as usize]);
            seen[slot as usize] = true;
            taken.push((slot, buffer));
        }

        assert_eq!(len(&set), 0);
        assert!(seen.into_iter().all(|seen| seen));
        assert!(set.take().is_none());

        // Return taken test buffers so the freelist owns deallocation.
        for (slot, buffer) in taken {
            set.put(slot, buffer);
        }
    }

    #[test]
    fn test_freelist_uses_striped_power_of_two_words() {
        // Covers target parallelism, capping when capacity is too small, and
        // capacity-driven word growth for large slot counts.
        let cases = [
            (1, 1, 1),
            (2, 2, 2),
            (3, 4, 2),
            (4, 4, 4),
            (12, 9, 8),
            (16, 8, 8),
            (64, 8, 8),
            (512, 8, 8),
            (513, 8, 16),
            (4097, 8, 128),
        ];

        for (capacity, parallelism, expected_words) in cases {
            let set = Freelist::new(NZU32!(capacity), NZUsize!(parallelism), TEST_LAYOUT, false);
            assert_eq!(num_words(&set), expected_words);
            assert!(num_words(&set).is_power_of_two());

            // Validate the striped mapping and its inverse for every slot that
            // can actually be handed out by this freelist.
            for slot in 0..capacity {
                let (word_index, mask) = set.slot_word(slot);
                let bit = mask.trailing_zeros() as usize;
                assert!(word_index < expected_words);
                assert_eq!(set.slot_index(word_index, bit), slot);
            }
        }
    }

    #[test]
    fn test_freelist_put_batch_handles_empty_single_and_multi_entry_paths() {
        let set = Freelist::new(NZU32!(8), NZUsize!(8), TEST_LAYOUT, false);

        // Empty batches are a no-op and must not make anything available.
        set.put_batch(Vec::new());
        assert_eq!(len(&set), 0);

        // Reserve the full slot range
        let mut created = Vec::new();
        for expected in 0..8 {
            let (slot, buffer) = set.try_create(false).unwrap();
            assert_eq!(slot, expected);
            created.push(Some(buffer));
        }

        // A single-entry batch delegates to `put`, preserving the cheaper
        // one-buffer path.
        let buffer = created[3].take().unwrap();
        set.put_batch(vec![(3, buffer)]);
        assert_eq!(len(&set), 1);

        let mut taken = Vec::new();
        assert_eq!(
            set.take_batch(1, |slot, buffer| taken.push((slot, buffer))),
            1
        );
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].0, 3);
        let single = taken.pop().expect("single entry was taken");

        // Multi-entry batches should make every slot available and preserve ownership
        // of each parked buffer until it is taken.
        let mut batch = Vec::new();
        for slot in [1, 5, 7] {
            let buffer = created[slot as usize].take().unwrap();
            batch.push((slot, buffer));
        }
        set.put_batch(batch);
        assert_eq!(len(&set), 3);

        assert_eq!(
            set.take_batch(3, |slot, buffer| taken.push((slot, buffer))),
            3
        );
        let mut slots = taken.iter().map(|(slot, _)| *slot).collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![1, 5, 7]);
        assert_eq!(len(&set), 0);

        // Return taken test buffers so the freelist owns deallocation.
        set.put(single.0, single.1);
        for (slot, buffer) in taken {
            set.put(slot, buffer);
        }
        for (slot, buffer) in created.into_iter().enumerate() {
            if let Some(buffer) = buffer {
                set.put(slot as u32, buffer);
            }
        }
    }

    #[test]
    fn test_freelist_put_batch_uses_heap_masks_when_word_count_exceeds_inline_capacity() {
        // A capacity of 8193 requires more than 128 bitmap words after rounding,
        // forcing `put_batch` to use heap scratch for its per-word masks.
        let set = Freelist::new(NZU32!(8193), NZUsize!(65), TEST_LAYOUT, false);
        assert!(num_words(&set) > INLINE_PUT_BATCH_MASKS);

        // Reserve through the highest slot so the original sparse slots are
        // valid while only those slots are published to the freelist.
        let mut created = Vec::new();
        for expected in 0..8193 {
            let (slot, buffer) = set.try_create(false).expect("slot");
            assert_eq!(slot, expected);
            created.push(Some(buffer));
        }

        let mut batch = Vec::new();
        for slot in [0, 1, 64, 8192] {
            let buffer = created[slot as usize].take().expect("slot buffer");
            batch.push((slot, buffer));
        }
        set.put_batch(batch);
        assert_eq!(len(&set), 4);

        let mut taken = Vec::new();
        assert_eq!(
            set.take_batch(8, |slot, buffer| taken.push((slot, buffer))),
            4
        );
        let mut slots = taken.iter().map(|(slot, _)| *slot).collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![0, 1, 64, 8192]);
        assert_eq!(len(&set), 0);

        // Return taken test buffers so the freelist owns deallocation.
        for (slot, buffer) in taken {
            set.put(slot, buffer);
        }
        for (slot, buffer) in created.into_iter().enumerate() {
            if let Some(buffer) = buffer {
                set.put(slot as u32, buffer);
            }
        }
    }

    #[test]
    fn test_freelist_drain_returns_all_available_slots() {
        let set = Freelist::new(NZU32!(4), NZUsize!(4), TEST_LAYOUT, false);
        let (slot0, buffer0) = set.try_create(false).unwrap();
        let (slot1, buffer1) = set.try_create(false).unwrap();
        let (slot2, buffer2) = set.try_create(false).unwrap();
        let (slot3, buffer3) = set.try_create(false).unwrap();
        assert_eq!([slot0, slot1, slot2, slot3], [0, 1, 2, 3]);

        set.put(slot0, buffer0);
        set.put(slot2, buffer2);
        set.put(slot3, buffer3);

        assert_eq!(set.drain(), 3);
        assert_eq!(len(&set), 0);

        // Return taken test buffer so the freelist owns deallocation.
        set.put(slot1, buffer1);
    }

    #[test]
    fn test_freelist_take_batch_handles_zero_single_and_partial_fill() {
        // Put fewer slots than the largest requested batch to cover exact,
        // partial, and empty refill behavior in one setup.
        let set = Freelist::new(NZU32!(4), NZUsize!(4), TEST_LAYOUT, false);
        for expected in [0, 1, 2] {
            let (slot, buffer) = set.try_create(false).expect("slot");
            assert_eq!(slot, expected);
            set.put(slot, buffer);
        }

        let mut taken = Vec::new();
        let mut record = |slot, buffer| taken.push((slot, buffer));

        // `max == 0` must return immediately and must not call the callback.
        assert_eq!(set.take_batch(0, &mut record), 0);

        // `max == 1` should still claim exactly one slot.
        assert_eq!(set.take_batch(1, &mut record), 1);

        // A request larger than the remaining occupancy should return only
        // the slots that were actually available.
        assert_eq!(set.take_batch(8, &mut record), 2);

        // Once empty, neither the batch nor single path may invoke the callback.
        assert_eq!(set.take_batch(8, &mut record), 0);
        assert_eq!(set.take_batch(1, &mut record), 0);
        assert_eq!(taken.len(), 3);

        let mut slots = taken.iter().map(|(slot, _)| *slot).collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![0, 1, 2]);

        // Return taken test buffers so the freelist owns deallocation.
        for (slot, buffer) in taken {
            set.put(slot, buffer);
        }
    }

    #[test]
    fn test_freelist_take_batch_breaks_after_filling_target_in_home_word() {
        let set = Freelist::new(NZU32!(16), NZUsize!(8), TEST_LAYOUT, true);
        let start_word = SlotBitmapProbe::new(set.word_mask, set.word_shift).word_index(0);
        let slot0 = set.slot_index(start_word, 0);
        let slot1 = set.slot_index(start_word, 1);

        // A two-slot batch should fill from this thread's first probed word
        // and stop immediately.
        let mut taken = Vec::new();
        assert_eq!(
            set.take_batch(2, |slot, buffer| taken.push((slot, buffer))),
            2
        );

        let mut slots = taken.iter().map(|(slot, _)| *slot).collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![slot0, slot1]);
        assert_eq!(len(&set), 14);

        // Return taken test buffers so the freelist owns deallocation.
        for (slot, buffer) in taken {
            set.put(slot, buffer);
        }
    }

    #[test]
    fn test_freelist_take_batch_stops_mid_word_when_limit_is_reached() {
        let set = Freelist::new(NZU32!(24), NZUsize!(8), TEST_LAYOUT, true);
        let start_word = SlotBitmapProbe::new(set.word_mask, set.word_shift).word_index(0);
        // This thread's first probed word contains three slots, so the batch
        // claim has to stop after clearing only the requested number of bits.
        let slots = [
            set.slot_index(start_word, 0),
            set.slot_index(start_word, 1),
            set.slot_index(start_word, 2),
        ];

        let mut taken = Vec::new();
        assert_eq!(
            set.take_batch(2, |slot, buffer| taken.push((slot, buffer))),
            2
        );
        assert_eq!(len(&set), 22);

        // The third slot should remain free and be retrievable normally.
        let remaining = set.take().expect("one slot should remain free");
        let mut seen = taken.iter().map(|(slot, _)| *slot).collect::<Vec<_>>();
        seen.push(remaining.0);
        seen.sort_unstable();
        assert_eq!(seen, slots);

        // Return taken test buffers so the freelist owns deallocation.
        for (slot, buffer) in taken {
            set.put(slot, buffer);
        }
        set.put(remaining.0, remaining.1);
    }

    #[test]
    fn test_slot_bitmap_probe_selectors_respect_offset_and_limit() {
        // The probe offset should rotate priority without selecting bits that
        // are not present in the original word.
        let word = (1u64 << 1) | (1u64 << 5) | (1u64 << 9) | (1u64 << 20);

        let probe_0 = SlotBitmapProbe {
            start_word: 0,
            word_mask: 0,
            bit_offset: 0,
        };
        let probe_6 = SlotBitmapProbe {
            start_word: 0,
            word_mask: 0,
            bit_offset: 6,
        };

        assert_eq!(probe_0.select_set_bit(word), 1);
        assert_eq!(probe_6.select_set_bit(word), 9);

        let selected = probe_6.select_set_bits(word, 2);
        // Starting after bit 6, the first two set bits are 9 and 20.
        assert_eq!(selected.count_ones(), 2);
        assert_eq!(selected & !word, 0);
        assert_eq!(selected, (1u64 << 9) | (1u64 << 20));

        let probe_32 = SlotBitmapProbe {
            start_word: 0,
            word_mask: 0,
            bit_offset: 32,
        };
        let wrap_word = (1u64 << 4) | (1u64 << 40);
        let selected = probe_32.select_set_bits(wrap_word, 2);
        // Starting after bit 32, selection should wrap after taking bit 40.
        assert_eq!(selected, wrap_word);
    }

    #[test]
    fn test_slot_bitmap_probe_offsets_spread_home_word_collisions() {
        // For an 8-word freelist, thread ids spaced by 8 share home word 0.
        // Spread their bit offsets across the word instead of assigning
        // adjacent offsets.
        assert_eq!(
            [
                SlotBitmapProbe::bit_offset(0, 3),
                SlotBitmapProbe::bit_offset(8, 3),
                SlotBitmapProbe::bit_offset(16, 3),
                SlotBitmapProbe::bit_offset(24, 3),
                SlotBitmapProbe::bit_offset(32, 3),
                SlotBitmapProbe::bit_offset(40, 3),
                SlotBitmapProbe::bit_offset(48, 3),
                SlotBitmapProbe::bit_offset(56, 3),
            ],
            [0, 32, 16, 48, 8, 40, 24, 56]
        );

        // The same collision groups should spread for the 64-word network
        // geometry.
        assert_eq!(
            [
                SlotBitmapProbe::bit_offset(0, 6),
                SlotBitmapProbe::bit_offset(64, 6),
                SlotBitmapProbe::bit_offset(128, 6),
                SlotBitmapProbe::bit_offset(192, 6),
                SlotBitmapProbe::bit_offset(256, 6),
                SlotBitmapProbe::bit_offset(320, 6),
                SlotBitmapProbe::bit_offset(384, 6),
                SlotBitmapProbe::bit_offset(448, 6),
            ],
            [0, 32, 16, 48, 8, 40, 24, 56]
        );
    }

    #[test]
    fn test_freelist_take_retries_after_losing_a_same_bit_race() {
        // Force repeated same-word contention on a single free slot. Some
        // contenders should observe a stale non-zero word and follow the retry
        // path before discovering that another thread already claimed the slot.
        for _ in 0..32 {
            let set = Arc::new(Freelist::new(NZU32!(1), NZUsize!(1), TEST_LAYOUT, false));
            let (slot, buffer) = set.try_create(false).unwrap();
            assert_eq!(slot, 0);
            set.put(slot, buffer);

            // Align the contenders so several can race on the same observed
            // word instead of serializing before `take`.
            let barrier = Arc::new(Barrier::new(16));
            let successes = Arc::new(StdAtomicUsize::new(0));
            let (claimed_tx, claimed_rx) = std::sync::mpsc::channel();
            let mut handles = Vec::new();

            for _ in 0..16 {
                let set = Arc::clone(&set);
                let barrier = Arc::clone(&barrier);
                let successes = Arc::clone(&successes);
                let claimed_tx = claimed_tx.clone();
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    if let Some(entry) = set.take() {
                        successes.fetch_add(1, AtomicOrdering::Relaxed);
                        claimed_tx.send(entry).expect("send claimed entry");
                    }
                }));
            }

            for handle in handles {
                handle.join().expect("worker should not panic");
            }

            assert_eq!(successes.load(AtomicOrdering::Relaxed), 1);
            assert_eq!(len(&set), 0);

            let claimed = claimed_rx.recv().expect("one thread claimed the slot");
            assert!(claimed_rx.try_recv().is_err());
            // Return the claimed buffer so the freelist owns deallocation.
            set.put(claimed.0, claimed.1);
        }
    }

    #[test]
    fn test_freelist_drop_drains_remaining_buffers() {
        // Dropping a non-empty freelist must drop any buffers still parked in
        // globally free slots.
        let set = Freelist::new(NZU32!(2), NZUsize!(2), TEST_LAYOUT, false);
        for expected in [0, 1] {
            let (slot, buffer) = set.try_create(false).expect("slot");
            assert_eq!(slot, expected);
            set.put(slot, buffer);
        }
        drop(set);
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use commonware_utils::{sync::Mutex, NZUsize, NZU32};
    use loom::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread,
    };

    // This module uses loom to model the freelist's ownership protocol between
    // bitmap bits and parking cells: a producer parks a buffer, publishes its
    // bit, and exactly one consumer clears that bit before reading the cell.
    // The models keep capacities small so loom can exhaustively explore the
    // interleavings that stress this protocol: same-word RMW composition,
    // striped scans across independent bitmap words, stale relaxed candidate
    // loads, and the Release/Acquire edge that makes a parked buffer visible
    // after its bit is claimed. Geometry-matrix tests cover single-word/single-bit,
    // single-word/multi-bit, multi-word/single-bit, and multi-word/multi-bit
    // layouts so both degenerate and striped cases stay exercised.

    fn single_word_freelist(capacity: u32) -> Freelist {
        Freelist::new(
            NZU32!(capacity),
            NZUsize!(1),
            Layout::from_size_align(64, 64).unwrap(),
            false,
        )
    }

    // Each geometry gives a model a small bitmap layout: one or more active
    // bitmap words, with either one or multiple free bits per active word.
    #[derive(Clone, Copy, Debug)]
    enum Geometry {
        SingleWordSingleBit,
        SingleWordMultiBit,
        MultiWordSingleBit,
        MultiWordMultiBit,
    }

    impl Geometry {
        // Builds a freelist with this geometry's bitmap shape.
        fn freelist(self) -> Freelist {
            match self {
                Self::SingleWordSingleBit => single_word_freelist(1),
                Self::SingleWordMultiBit => single_word_freelist(2),
                Self::MultiWordSingleBit => Freelist::new(
                    NZU32!(4),
                    NZUsize!(4),
                    Layout::from_size_align(64, 64).unwrap(),
                    false,
                ),
                Self::MultiWordMultiBit => Freelist::new(
                    NZU32!(4),
                    NZUsize!(2),
                    Layout::from_size_align(64, 64).unwrap(),
                    false,
                ),
            }
        }

        // Returns the slot ids that are active in this geometry. The order is
        // used by batch tests, so layouts with multiple bits in a word keep
        // same-word slots adjacent.
        fn slots(self) -> &'static [u32] {
            match self {
                Self::SingleWordSingleBit => &[0],
                Self::SingleWordMultiBit => &[0, 1],
                Self::MultiWordSingleBit => &[0, 1, 2, 3],
                Self::MultiWordMultiBit => &[0, 2, 1, 3],
            }
        }

        // Returns a bit mask of active slot ids for duplicate and completeness
        // checks in the models.
        fn slot_mask(self) -> usize {
            self.slots()
                .iter()
                .fold(0usize, |mask, &slot| mask | (1usize << slot))
        }
    }

    const ALL_GEOMETRIES: [Geometry; 4] = [
        Geometry::SingleWordSingleBit,
        Geometry::SingleWordMultiBit,
        Geometry::MultiWordSingleBit,
        Geometry::MultiWordMultiBit,
    ];

    const BATCH_GEOMETRIES: [Geometry; 3] = [
        Geometry::SingleWordMultiBit,
        Geometry::MultiWordSingleBit,
        Geometry::MultiWordMultiBit,
    ];

    const STRIPED_GEOMETRIES: [Geometry; 2] =
        [Geometry::MultiWordSingleBit, Geometry::MultiWordMultiBit];

    const MULTI_BIT_GEOMETRIES: [Geometry; 2] =
        [Geometry::SingleWordMultiBit, Geometry::MultiWordMultiBit];

    fn model<F>(geometries: &[Geometry], test: F)
    where
        F: Fn(Geometry, Arc<Freelist>) + Clone + Send + Sync + 'static,
    {
        for &geometry in geometries {
            let test = test.clone();
            loom::model(move || {
                test(geometry, Arc::new(geometry.freelist()));
            });
        }
    }

    // Owns buffers that a loom model has taken from the freelist. This
    // keeps the test-side ownership rule in one place: every created buffer
    // must be returned to the same freelist before that freelist is dropped.
    struct Leases {
        freelist: Arc<Freelist>,
        buffers: Mutex<Vec<(u32, PooledBuffer)>>,
    }

    impl Leases {
        fn new(freelist: Arc<Freelist>) -> Arc<Self> {
            Arc::new(Self {
                freelist,
                buffers: Mutex::new(Vec::new()),
            })
        }

        fn reserve(freelist: Arc<Freelist>) -> (Arc<Self>, Vec<(u32, PooledBuffer)>) {
            let entries = Self::entries(&freelist);
            (Self::new(freelist), entries)
        }

        fn entries(freelist: &Freelist) -> Vec<(u32, PooledBuffer)> {
            let mut entries = Vec::new();
            while let Some(entry) = freelist.try_create(false) {
                entries.push(entry);
            }
            entries
        }

        fn push(&self, slot: u32, buffer: PooledBuffer) {
            self.buffers.lock().push((slot, buffer));
        }

        fn push_expected(
            &self,
            seen: &AtomicUsize,
            expected: usize,
            slot: u32,
            buffer: PooledBuffer,
        ) {
            let mask = 1usize << slot;
            assert_ne!(expected & mask, 0);
            let previous = seen.fetch_or(mask, Ordering::Relaxed);
            assert_eq!(previous & mask, 0);
            self.push(slot, buffer);
        }
    }

    impl Drop for Leases {
        fn drop(&mut self) {
            for (slot, buffer) in self.buffers.lock().drain(..) {
                self.freelist.put(slot, buffer);
            }
        }
    }

    #[test]
    fn put_publishes_before_take() {
        // `put` writes the parking cell before publishing the bit with a
        // Release RMW. The taker spins until it can clear that bit with an
        // Acquire RMW, then reads the same cell.
        //
        // If the publish/claim edge is weakened, loom should be able to
        // schedule the cell read without seeing the prior cell write.
        model(&ALL_GEOMETRIES, |geometry, freelist| {
            let slot = geometry.slots()[0];
            let (_, buffer) = freelist.try_create(false).unwrap();
            let leases = Leases::new(freelist.clone());

            let writer = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put(slot, buffer)
            });

            let reader = thread::spawn({
                let freelist = freelist.clone();
                let leases = leases.clone();
                move || loop {
                    if let Some((taken, buffer)) = freelist.take() {
                        assert_eq!(taken, slot);
                        leases.push(taken, buffer);
                        break;
                    }
                    thread::yield_now();
                }
            });

            writer.join().unwrap();
            reader.join().unwrap();
        });
    }

    #[test]
    fn concurrent_puts_merge_disjoint_bits() {
        // Two producers return different slots that live in the same bitmap
        // word. Their atomic `fetch_or` operations must merge the bits: neither
        // producer may overwrite the other's publication.
        //
        // The consumer runs after both producers finish so this test isolates
        // lost producer updates from consumer-side claim races and from the
        // publish/claim visibility tests below.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(2));
            let seen = Arc::new(AtomicUsize::new(0));
            let expected = 0b11;
            let (leases, mut entries) = Leases::reserve(freelist.clone());
            let (slot0, buffer0) = entries.pop().unwrap();
            let (slot1, buffer1) = entries.pop().unwrap();

            let first = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put(slot0, buffer0)
            });

            let second = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put(slot1, buffer1)
            });

            first.join().unwrap();
            second.join().unwrap();

            assert_eq!(
                freelist.take_batch(2, |slot, buffer| {
                    leases.push_expected(&seen, expected, slot, buffer)
                }),
                2
            );
            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn concurrent_put_batches_merge_disjoint_bits() {
        // Each producer stages two slots and then publishes its per-word mask
        // with one Release `fetch_or`. Because all four slots share a word,
        // this specifically checks that two batch producers merge their masks
        // instead of losing either batch.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(4));
            let seen = Arc::new(AtomicUsize::new(0));
            let expected = 0b1111;
            let (leases, mut entries) = Leases::reserve(freelist.clone());
            let second_entries = entries.split_off(2);

            let first = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put_batch(entries)
            });

            let second = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put_batch(second_entries)
            });

            first.join().unwrap();
            second.join().unwrap();

            assert_eq!(
                freelist.take_batch(4, |slot, buffer| {
                    leases.push_expected(&seen, expected, slot, buffer)
                }),
                4
            );
            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn put_and_take_compose_on_partially_free_word() {
        // Slot 0 starts free, then a producer returns slot 1 while `take` races
        // on the same bitmap word. The producer's `fetch_or` must compose with
        // the consumer's `fetch_and`: clearing the existing bit must not lose
        // the newly published bit, and publishing the new bit must not
        // resurrect a claimed bit.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(2));
            let (leases, mut entries) = Leases::reserve(freelist.clone());
            let initial_entry = entries.pop().unwrap();
            let writer_entry = entries.pop().unwrap();
            assert!(entries.pop().is_none());
            freelist.put(initial_entry.0, initial_entry.1);

            let seen = Arc::new(AtomicUsize::new(0));
            let expected = 0b11;

            let writer = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put(writer_entry.0, writer_entry.1)
            });

            let taker = thread::spawn({
                let freelist = freelist.clone();
                let seen = seen.clone();
                let leases = leases.clone();
                move || {
                    let (slot, buffer) = freelist.take().expect("slot 0 starts free");
                    leases.push_expected(&seen, expected, slot, buffer);
                }
            });

            writer.join().unwrap();
            taker.join().unwrap();

            // The taker may run before slot 1 is published. After the writer
            // has joined, any slot not claimed during the race must still be
            // available exactly once.
            while let Some((slot, buffer)) = freelist.take() {
                leases.push_expected(&seen, expected, slot, buffer);
            }

            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn put_and_take_batch_compose_on_partially_free_word() {
        // This is the batch-claim version of the partially-free word race:
        // `take_batch` may speculatively choose candidates from a stale relaxed
        // load while a producer publishes a different bit in the same word.
        // Only bits actually cleared by the batch taker may drive callbacks,
        // and missed bits must remain available.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(2));
            let (leases, mut entries) = Leases::reserve(freelist.clone());
            let initial_entry = entries.pop().unwrap();
            let writer_entry = entries.pop().unwrap();
            assert!(entries.pop().is_none());
            freelist.put(initial_entry.0, initial_entry.1);

            let seen = Arc::new(AtomicUsize::new(0));
            let expected = 0b11;

            let writer = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put(writer_entry.0, writer_entry.1)
            });

            let batch_taker = thread::spawn({
                let freelist = freelist.clone();
                let seen = seen.clone();
                let leases = leases.clone();
                move || {
                    let count = freelist.take_batch(2, |slot, buffer| {
                        leases.push_expected(&seen, expected, slot, buffer);
                    });
                    assert!((1..=2).contains(&count));
                }
            });

            writer.join().unwrap();
            batch_taker.join().unwrap();

            // If the batch taker ran before slot 1 was published, the slot must
            // still be visible after the writer completes.
            while let Some((slot, buffer)) = freelist.take() {
                leases.push_expected(&seen, expected, slot, buffer);
            }

            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn put_batch_and_drain_compose_on_partially_free_word() {
        // Slot 0 starts free, then a batch producer stages slots 1 and 2 and
        // publishes them with one `fetch_or`. A concurrent `drain` clears the
        // whole word with `swap(0)`. The two RMWs must compose: the drainer may
        // get only slot 0 or all three slots, but the slots it misses must
        // remain available after the writer completes.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(3));
            let mut entries = Leases::entries(&freelist);
            let writer_entry0 = entries.pop().unwrap();
            let writer_entry1 = entries.pop().unwrap();
            let initial_entry = entries.pop().unwrap();
            assert!(entries.pop().is_none());
            freelist.put(initial_entry.0, initial_entry.1);

            let drained = Arc::new(AtomicUsize::new(0));

            let writer = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put_batch([writer_entry0, writer_entry1])
            });

            let drainer = thread::spawn({
                let freelist = freelist.clone();
                let drained = drained.clone();
                move || {
                    let count = freelist.drain();
                    assert!(matches!(count, 1 | 3));
                    drained.store(count, Ordering::Relaxed);
                }
            });

            writer.join().unwrap();
            drainer.join().unwrap();

            let total = drained.load(Ordering::Relaxed) + freelist.drain();
            assert_eq!(total, 3);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn two_takers_cannot_claim_one_slot() {
        // Both takers may observe the same relaxed non-zero candidate word.
        // Only one may win the later `fetch_and` claim.
        //
        // This is the minimal stale-candidate case: the relaxed load is allowed
        // to be old, but the returned value from `fetch_and` must decide
        // ownership.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(2));
            let (_, buffer) = freelist.try_create(false).unwrap();
            freelist.put(0, buffer);

            let seen = Arc::new(AtomicUsize::new(0));
            let expected = 0b1;
            let mut handles = Vec::new();
            let leases = Leases::new(freelist.clone());

            for _ in 0..2 {
                handles.push(thread::spawn({
                    let freelist = freelist.clone();
                    let seen = seen.clone();
                    let leases = leases.clone();
                    move || {
                        if let Some((slot, buffer)) = freelist.take() {
                            leases.push_expected(&seen, expected, slot, buffer);
                        }
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(seen.load(Ordering::Relaxed), expected);
        });
    }

    #[test]
    fn stale_candidate_can_claim_republished_same_slot() {
        // A relaxed candidate load is not a reservation. One taker may observe
        // slot 0 as free, lose the first claim race, and later clear a
        // re-published bit for the same slot. The valid outcome is two
        // sequential ownership transfers of slot 0, each synchronized by the
        // Acquire claim that actually cleared the bit it returns.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(1));
            let (leases, mut entries) = Leases::reserve(freelist.clone());
            let entry = entries.pop().unwrap();
            assert!(entries.pop().is_none());
            freelist.put(entry.0, entry.1);

            let transfers = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            for _ in 0..2 {
                handles.push(thread::spawn({
                    let freelist = freelist.clone();
                    let transfers = transfers.clone();
                    let leases = leases.clone();
                    move || loop {
                        if let Some((slot, buffer)) = freelist.take() {
                            assert_eq!(slot, 0);
                            let transfer = transfers.fetch_add(1, Ordering::Relaxed) + 1;
                            if transfer == 1 {
                                freelist.put(slot, buffer);
                            } else {
                                leases.push(slot, buffer);
                            }
                            break;
                        }
                        thread::yield_now();
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(transfers.load(Ordering::Relaxed), 2);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn batch_claims_survive_intervening_rmw_sequence() {
        // `put_batch` publishes both bits with one Release RMW. This model
        // starts takers after publication to keep the state space small. The
        // writer/reader visibility edge for batch publication is covered by
        // `put_batch_publishes_to_take_batch`.
        //
        // What this case isolates is the two-taker claim sequence on the same
        // word: one taker may clear one bit, then the other taker reads the
        // word through that intervening RMW. Both slots must still be
        // transferred exactly once.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(2));
            let (leases, entries) = Leases::reserve(freelist.clone());
            freelist.put_batch(entries);

            let seen = Arc::new(AtomicUsize::new(0));
            let expected = 0b11;
            let mut handles = Vec::new();

            for _ in 0..2 {
                handles.push(thread::spawn({
                    let freelist = freelist.clone();
                    let seen = seen.clone();
                    let leases = leases.clone();
                    move || {
                        if let Some((slot, buffer)) = freelist.take() {
                            leases.push_expected(&seen, expected, slot, buffer);
                        }
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(seen.load(Ordering::Relaxed), expected);
        });
    }

    #[test]
    fn take_and_take_batch_do_not_duplicate_slots() {
        // A single-slot claim and a batch claim race over the same free set.
        // Each claimed slot is recorded once, any duplicate ownership transfer
        // trips the `previous & mask == 0` assertion.
        //
        // This covers the speculative batch claim path, where `take_batch`
        // first chooses candidate bits and then intersects them with the word
        // value returned by `fetch_and`.
        model(&BATCH_GEOMETRIES, |geometry, freelist| {
            let slots = geometry.slots();
            let expected = geometry.slot_mask();
            let (leases, entries) = Leases::reserve(freelist.clone());
            freelist.put_batch(entries);

            let seen = Arc::new(AtomicUsize::new(0));
            let batch_count = Arc::new(AtomicUsize::new(0));
            let batch_callbacks = Arc::new(AtomicUsize::new(0));

            let batch_taker = thread::spawn({
                let freelist = freelist.clone();
                let seen = seen.clone();
                let batch_count = batch_count.clone();
                let batch_callbacks = batch_callbacks.clone();
                let leases = leases.clone();
                move || {
                    let count = freelist.take_batch(slots.len(), |slot, buffer| {
                        batch_callbacks.fetch_add(1, Ordering::Relaxed);
                        leases.push_expected(&seen, expected, slot, buffer);
                    });
                    batch_count.store(count, Ordering::Relaxed);
                }
            });

            let single_taker = thread::spawn({
                let freelist = freelist.clone();
                let seen = seen.clone();
                let leases = leases.clone();
                move || {
                    if let Some((slot, buffer)) = freelist.take() {
                        leases.push_expected(&seen, expected, slot, buffer);
                    }
                }
            });

            batch_taker.join().unwrap();
            single_taker.join().unwrap();

            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert!(batch_count.load(Ordering::Relaxed) <= slots.len());
            assert_eq!(
                batch_count.load(Ordering::Relaxed),
                batch_callbacks.load(Ordering::Relaxed)
            );
        });
    }

    #[test]
    fn two_take_batches_do_not_duplicate_slots() {
        // Two batch refill paths can speculatively choose stale candidate bits
        // from relaxed word loads. Each callback must still be driven only by
        // bits that caller actually cleared with `fetch_and`.
        model(&MULTI_BIT_GEOMETRIES, |geometry, freelist| {
            let slots = geometry.slots();
            let expected = geometry.slot_mask();
            let (leases, entries) = Leases::reserve(freelist.clone());
            freelist.put_batch(entries);

            let seen = Arc::new(AtomicUsize::new(0));
            let total = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            for _ in 0..2 {
                handles.push(thread::spawn({
                    let freelist = freelist.clone();
                    let seen = seen.clone();
                    let total = total.clone();
                    let leases = leases.clone();
                    move || {
                        let count = freelist.take_batch(slots.len(), |slot, buffer| {
                            leases.push_expected(&seen, expected, slot, buffer);
                        });
                        total.fetch_add(count, Ordering::Relaxed);
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(total.load(Ordering::Relaxed), slots.len());
        });
    }

    #[test]
    fn two_take_batches_continue_after_losing_selected_bits() {
        // Both batch takers can speculatively select the same first two bits
        // from a stale relaxed word load. If one taker clears those bits first,
        // the other must use the word value returned by `fetch_and` and
        // continue on to the still-set third bit instead of stopping after a
        // zero-sized successful claim.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(3));
            let (leases, entries) = Leases::reserve(freelist.clone());
            freelist.put_batch(entries);

            let seen = Arc::new(AtomicUsize::new(0));
            let total = Arc::new(AtomicUsize::new(0));
            let expected = 0b111;
            let mut handles = Vec::new();

            for _ in 0..2 {
                handles.push(thread::spawn({
                    let freelist = freelist.clone();
                    let seen = seen.clone();
                    let total = total.clone();
                    let leases = leases.clone();
                    move || {
                        let count = freelist.take_batch(2, |slot, buffer| {
                            leases.push_expected(&seen, expected, slot, buffer);
                        });
                        total.fetch_add(count, Ordering::Relaxed);
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(total.load(Ordering::Relaxed), 3);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn put_batch_publishes_to_take_batch() {
        // This exercises the batch-specific publish and claim path end to end
        // across selected bitmap geometries: Release `fetch_or` publications
        // make parked cells visible, and Acquire `fetch_and` claims may
        // transfer one or more bits per word.
        //
        // The reader loops because loom may run it before the writer has
        // published anything. A zero-sized claim is just a retry, not an
        // observable failure.
        model(&BATCH_GEOMETRIES, |geometry, freelist| {
            let seen = Arc::new(AtomicUsize::new(0));
            let slots = geometry.slots();
            let expected = geometry.slot_mask();
            let (leases, entries) = Leases::reserve(freelist.clone());

            let writer = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put_batch(entries)
            });

            let reader = thread::spawn({
                let freelist = freelist.clone();
                let seen = seen.clone();
                let leases = leases.clone();
                move || {
                    while seen.load(Ordering::Relaxed) != expected {
                        let claimed = freelist.take_batch(slots.len(), |slot, buffer| {
                            leases.push_expected(&seen, expected, slot, buffer);
                        });

                        if claimed == 0 {
                            thread::yield_now();
                        }
                    }
                }
            });

            writer.join().unwrap();
            reader.join().unwrap();

            assert_eq!(seen.load(Ordering::Relaxed), expected);
        });
    }

    #[test]
    fn put_publishes_to_drain() {
        // `drain` uses an Acquire whole-word swap. Run it concurrently with
        // publication so this model checks the put-side Release edge rather
        // than relying on thread-spawn visibility from pre-populated state.
        //
        // If the swap does not synchronize with the successful put, loom's
        // tracked parking cell can observe the drainer reading the buffer
        // without seeing the writer's earlier cell initialization.
        model(&ALL_GEOMETRIES, |geometry, freelist| {
            let drained = Arc::new(AtomicUsize::new(0));
            let slot = geometry.slots()[0];
            let (_, buffer) = freelist.try_create(false).unwrap();

            let writer = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put(slot, buffer)
            });

            let drainer = thread::spawn({
                let freelist = freelist.clone();
                let drained = drained.clone();
                move || {
                    while drained.load(Ordering::Relaxed) == 0 {
                        let count = freelist.drain();
                        if count == 0 {
                            // The drainer may run before the writer publishes.
                            // A zero drain is a retry, not a failed assertion.
                            thread::yield_now();
                        } else {
                            assert_eq!(count, 1);
                            drained.store(count, Ordering::Relaxed);
                        }
                    }
                }
            });

            writer.join().unwrap();
            drainer.join().unwrap();

            assert_eq!(drained.load(Ordering::Relaxed), 1);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn put_batch_publishes_to_drain() {
        // A batch publish parks multiple cells before publishing the touched
        // bitmap word masks. The drainer loops until its Acquire swaps have
        // observed every publication and dropped every parked buffer.
        //
        // This is the drain analogue of `put_batch_publishes_to_take_batch`:
        // each whole-word swap must make all cells represented by the returned
        // word visible before they are dropped.
        model(&BATCH_GEOMETRIES, |geometry, freelist| {
            let drained = Arc::new(AtomicUsize::new(0));
            let slots = geometry.slots();
            let expected = slots.len();
            let entries = Leases::entries(&freelist);

            let writer = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put_batch(entries)
            });

            let drainer = thread::spawn({
                let freelist = freelist.clone();
                let drained = drained.clone();
                move || {
                    while drained.load(Ordering::Relaxed) < expected {
                        let count = freelist.drain();
                        if count == 0 {
                            // The drainer may run before the batch is published.
                            thread::yield_now();
                        } else {
                            let previous = drained.fetch_add(count, Ordering::Relaxed);
                            assert!(previous + count <= expected);
                        }
                    }
                }
            });

            writer.join().unwrap();
            drainer.join().unwrap();

            assert_eq!(drained.load(Ordering::Relaxed), expected);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn puts_and_take_scan_across_stripes() {
        // Publish slots across multiple bitmap words using the single-entry
        // `put` path. The reader uses repeated `take` calls, not `take_batch`,
        // so this checks that the single-slot scan path reaches every occupied
        // stripe and that each independent Release publication synchronizes
        // with the later Acquire claim.
        model(&STRIPED_GEOMETRIES, |geometry, freelist| {
            let seen = Arc::new(AtomicUsize::new(0));
            let expected = geometry.slot_mask();
            let (leases, entries) = Leases::reserve(freelist.clone());

            let writer = thread::spawn({
                let freelist = freelist.clone();
                move || {
                    for (slot, buffer) in entries {
                        freelist.put(slot, buffer);
                    }
                }
            });

            let reader = thread::spawn({
                let freelist = freelist.clone();
                let seen = seen.clone();
                let leases = leases.clone();
                move || {
                    while seen.load(Ordering::Relaxed) != expected {
                        if let Some((slot, buffer)) = freelist.take() {
                            leases.push_expected(&seen, expected, slot, buffer);
                        } else {
                            thread::yield_now();
                        }
                    }
                }
            });

            writer.join().unwrap();
            reader.join().unwrap();

            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn drain_and_take_do_not_duplicate_or_lose_slots() {
        // `drain` clears a whole word with `swap(0)` while `take` clears one
        // bit with `fetch_and`. Racing them should transfer ownership of each
        // parked buffer exactly once and leave no free bits behind.
        //
        // This also covers the synchronization shape used by `Drop`, which
        // drains any buffers that remain globally free.
        model(&BATCH_GEOMETRIES, |geometry, freelist| {
            let slots = geometry.slots();
            let expected = slots.len();
            let expected_mask = geometry.slot_mask();
            let (leases, entries) = Leases::reserve(freelist.clone());
            freelist.put_batch(entries);

            let drained = Arc::new(AtomicUsize::new(0));
            let taken = Arc::new(AtomicUsize::new(0));

            let drainer = thread::spawn({
                let freelist = freelist.clone();
                let drained = drained.clone();
                move || {
                    drained.store(freelist.drain(), Ordering::Relaxed);
                }
            });

            let taker = thread::spawn({
                let freelist = freelist.clone();
                let taken = taken.clone();
                let leases = leases.clone();
                move || {
                    if let Some((slot, buffer)) = freelist.take() {
                        leases.push_expected(&taken, expected_mask, slot, buffer);
                    }
                }
            });

            drainer.join().unwrap();
            taker.join().unwrap();

            assert_eq!(freelist.drain(), 0);
            assert_eq!(
                drained.load(Ordering::Relaxed)
                    + taken.load(Ordering::Relaxed).count_ones() as usize,
                expected
            );
        });
    }

    #[test]
    fn two_drains_do_not_duplicate_or_lose_slots() {
        // `drain` is a public whole-word `swap(0)` operation over every bitmap
        // word. Two drainers racing over the same free set must split ownership
        // according to the values returned by their swaps, and the total must
        // be exactly the original occupancy.
        model(&BATCH_GEOMETRIES, |geometry, freelist| {
            let slots = geometry.slots();
            let expected = slots.len();
            let entries = Leases::entries(&freelist);
            freelist.put_batch(entries);

            let total = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            for _ in 0..2 {
                handles.push(thread::spawn({
                    let freelist = freelist.clone();
                    let total = total.clone();
                    move || {
                        total.fetch_add(freelist.drain(), Ordering::Relaxed);
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(total.load(Ordering::Relaxed), expected);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn drain_and_take_batch_do_not_duplicate_or_lose_slots() {
        // This is the same whole-word `swap(0)` race as the single-slot drain
        // test, but the competing operation clears a speculative multi-bit
        // claim. It makes sure `take_batch` uses the word value returned by
        // `fetch_and`, not just the earlier relaxed load.
        model(&BATCH_GEOMETRIES, |geometry, freelist| {
            let slots = geometry.slots();
            let expected = slots.len();
            let expected_mask = geometry.slot_mask();
            let (leases, entries) = Leases::reserve(freelist.clone());
            freelist.put_batch(entries);

            let drained = Arc::new(AtomicUsize::new(0));
            let taken = Arc::new(AtomicUsize::new(0));
            let taken_slots = Arc::new(AtomicUsize::new(0));

            let drainer = thread::spawn({
                let freelist = freelist.clone();
                let drained = drained.clone();
                move || {
                    drained.store(freelist.drain(), Ordering::Relaxed);
                }
            });

            let batch_taker = thread::spawn({
                let freelist = freelist.clone();
                let taken = taken.clone();
                let taken_slots = taken_slots.clone();
                let leases = leases.clone();
                move || {
                    let count = freelist.take_batch(expected, |slot, buffer| {
                        leases.push_expected(&taken_slots, expected_mask, slot, buffer);
                    });
                    taken.store(count, Ordering::Relaxed);
                }
            });

            drainer.join().unwrap();
            batch_taker.join().unwrap();

            assert_eq!(freelist.drain(), 0);
            assert_eq!(
                taken.load(Ordering::Relaxed),
                taken_slots.load(Ordering::Relaxed).count_ones() as usize
            );
            assert_eq!(
                drained.load(Ordering::Relaxed) + taken.load(Ordering::Relaxed),
                expected
            );
        });
    }
}
