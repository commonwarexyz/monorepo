//! Striped global freelist for one buffer-pool size class.
//!
//! A [`Freelist`] owns the tracked buffers from one [`super::pool::BufferPool`]
//! size class that are not checked out and not held in a thread-local cache,
//! making those buffers available for reuse by any thread in the pool. Each
//! tracked buffer has a stable slot id within its size class.
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
//! The parking cell holds the [`AlignedBuffer`] while the slot is globally free.
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
//! ownership discipline: a slot is either checked out, parked in a thread-local
//! cache, or available in this freelist. Only the thread that owns a slot
//! outside the freelist may access that slot's parking cell.
use super::aligned::AlignedBuffer;
use crossbeam_utils::CachePadded;
use std::{
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
/// The bitmap is intentionally striped over a power-of-two number of words.
/// That makes the slot-to-word mapping cheap and keeps small freelists from
/// degenerating into a single hot atomic word.
pub struct Freelist {
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
    storage: Box<[UnsafeCell<MaybeUninit<AlignedBuffer>>]>,
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
    pub fn new(capacity: NonZeroU32, parallelism: NonZeroUsize) -> Self {
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

        Self {
            words,
            storage,
            word_mask,
            word_shift,
        }
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
    /// this freelist.
    #[inline]
    pub fn put(&self, slot: u32, buffer: AlignedBuffer) {
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
    /// the batch and must not already be available in this freelist.
    ///
    /// The iterator **must not panic** after yielding an entry.
    ///
    /// `BufferPool` callers use simple drain and array iterators, avoiding
    /// per-entry guards keeps this path allocation-free for ordinary batches.
    #[inline]
    pub fn put_batch(&self, entries: impl IntoIterator<Item = (u32, AlignedBuffer)>) {
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
    /// The caller must own every slot, slots must be unique, and none of the
    /// slots may already be available in this freelist. The iterator must not
    /// panic after yielding an entry, because staged-but-not-inserted buffers
    /// would no longer be owned by the caller and would not yet be reachable
    /// through the bitmap.
    #[inline(always)]
    fn put_entries(
        &self,
        masks: &mut [u64],
        slot: u32,
        buffer: AlignedBuffer,
        next_slot: u32,
        next_buffer: AlignedBuffer,
        entries: impl Iterator<Item = (u32, AlignedBuffer)>,
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
    fn stage_put(&self, masks: &mut [u64], slot: u32, buffer: AlignedBuffer) {
        // Park first, then stage the bit for the later per-word insert.
        self.park(slot, buffer);
        let (word_index, mask) = self.slot_word(slot);
        masks[word_index] |= mask;
    }

    /// Takes any one available slot from the global freelist.
    ///
    /// On success, ownership of the returned slot is transferred to the caller.
    ///
    /// The search starts from a stable per-thread home word and scans the other
    /// stripes only on miss. Within a word, `fetch_and` claims one bit. That is
    /// important: unlike a full-word CAS loop, two threads removing different
    /// bits from the same word can both succeed.
    #[inline]
    pub fn take(&self) -> Option<(u32, AlignedBuffer)> {
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
    /// Ownership of each claimed slot is transferred to `on_entry`.
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
    pub fn take_batch(&self, max: usize, mut on_entry: impl FnMut(u32, AlignedBuffer)) -> usize {
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
                drop(self.unpark(slot));
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
    fn park(&self, slot: u32, buffer: AlignedBuffer) {
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
    fn unpark(&self, slot: u32) -> AlignedBuffer {
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
        // aligned allocations are released before the raw storage backing the
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

    #[test]
    fn test_freelist_returns_each_slot_once() {
        // Use a non-power-of-two capacity to cover partial final words while
        // keeping the expected slot set easy to inspect.
        let set = Freelist::new(NZU32!(3), NZUsize!(1));

        for slot in 0..3 {
            set.put(slot, AlignedBuffer::new(64, 64));
        }

        // Every free slot should be returned exactly once, and the
        // freelist should report empty afterward.
        let mut seen = [false; 3];
        for _ in 0..3 {
            let (slot, buffer) = set.take().expect("slot should be available");
            assert!(!seen[slot as usize]);
            seen[slot as usize] = true;
            drop(buffer);
        }

        assert_eq!(len(&set), 0);
        assert!(seen.into_iter().all(|seen| seen));
        assert!(set.take().is_none());
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
            let set = Freelist::new(NZU32!(capacity), NZUsize!(parallelism));
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
        let set = Freelist::new(NZU32!(8), NZUsize!(8));

        // Empty batches are a no-op and must not make anything available.
        set.put_batch(Vec::new());
        assert_eq!(len(&set), 0);

        // A single-entry batch delegates to `put`, preserving the cheaper
        // one-buffer path.
        set.put_batch(vec![(3, AlignedBuffer::new(64, 64))]);
        assert_eq!(len(&set), 1);

        let mut taken = Vec::new();
        assert_eq!(
            set.take_batch(1, |slot, buffer| taken.push((slot, buffer))),
            1
        );
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].0, 3);
        taken.clear();

        // Multi-entry batches should make every slot available and preserve ownership
        // of each parked buffer until it is taken.
        set.put_batch(vec![
            (1, AlignedBuffer::new(64, 64)),
            (5, AlignedBuffer::new(64, 64)),
            (7, AlignedBuffer::new(64, 64)),
        ]);
        assert_eq!(len(&set), 3);

        assert_eq!(
            set.take_batch(3, |slot, buffer| taken.push((slot, buffer))),
            3
        );
        let slots = taken.into_iter().map(|(slot, buffer)| {
            drop(buffer);
            slot
        });
        let mut slots = slots.collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![1, 5, 7]);
        assert_eq!(len(&set), 0);
    }

    #[test]
    fn test_freelist_put_batch_uses_heap_masks_when_word_count_exceeds_inline_capacity() {
        // A capacity of 8193 requires more than 128 bitmap words after rounding,
        // forcing `put_batch` to use heap scratch for its per-word masks.
        let set = Freelist::new(NZU32!(8193), NZUsize!(65));
        assert!(num_words(&set) > INLINE_PUT_BATCH_MASKS);

        set.put_batch(vec![
            (0, AlignedBuffer::new(64, 64)),
            (1, AlignedBuffer::new(64, 64)),
            (64, AlignedBuffer::new(64, 64)),
            (8192, AlignedBuffer::new(64, 64)),
        ]);
        assert_eq!(len(&set), 4);

        let mut taken = Vec::new();
        assert_eq!(
            set.take_batch(8, |slot, buffer| taken.push((slot, buffer))),
            4
        );
        let mut slots = taken
            .into_iter()
            .map(|(slot, buffer)| {
                drop(buffer);
                slot
            })
            .collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![0, 1, 64, 8192]);
        assert_eq!(len(&set), 0);
    }

    #[test]
    fn test_freelist_drain_returns_all_available_slots() {
        let set = Freelist::new(NZU32!(4), NZUsize!(4));
        for slot in [0u32, 2, 3] {
            set.put(slot, AlignedBuffer::new(64, 64));
        }

        assert_eq!(set.drain(), 3);
        assert_eq!(len(&set), 0);
    }

    #[test]
    fn test_freelist_take_batch_handles_zero_single_and_partial_fill() {
        // Put fewer slots than the largest requested batch to cover exact,
        // partial, and empty refill behavior in one setup.
        let set = Freelist::new(NZU32!(4), NZUsize!(4));
        for slot in 0..3 {
            set.put(slot, AlignedBuffer::new(64, 64));
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

        let mut slots = taken
            .into_iter()
            .map(|(slot, buffer)| {
                drop(buffer);
                slot
            })
            .collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![0, 1, 2]);
    }

    #[test]
    fn test_freelist_take_batch_breaks_after_filling_target_in_home_word() {
        let set = Freelist::new(NZU32!(16), NZUsize!(8));
        let start_word = SlotBitmapProbe::new(set.word_mask, set.word_shift).word_index(0);
        let slot0 = set.slot_index(start_word, 0);
        let slot1 = set.slot_index(start_word, 1);

        // Put exactly two slots in this thread's first probed word. A
        // two-slot batch should fill from that word and stop immediately.
        set.put(slot0, AlignedBuffer::new(64, 64));
        set.put(slot1, AlignedBuffer::new(64, 64));

        let mut taken = Vec::new();
        assert_eq!(
            set.take_batch(2, |slot, buffer| taken.push((slot, buffer))),
            2
        );

        let mut slots = taken
            .into_iter()
            .map(|(slot, buffer)| {
                drop(buffer);
                slot
            })
            .collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![slot0, slot1]);
        assert_eq!(len(&set), 0);
    }

    #[test]
    fn test_freelist_take_batch_stops_mid_word_when_limit_is_reached() {
        let set = Freelist::new(NZU32!(24), NZUsize!(8));
        let start_word = SlotBitmapProbe::new(set.word_mask, set.word_shift).word_index(0);
        // Put three slots in the same word so the batch claim has to stop after
        // clearing only the requested number of bits.
        let slots = [
            set.slot_index(start_word, 0),
            set.slot_index(start_word, 1),
            set.slot_index(start_word, 2),
        ];

        for slot in slots {
            set.put(slot, AlignedBuffer::new(64, 64));
        }

        let mut taken = Vec::new();
        assert_eq!(
            set.take_batch(2, |slot, buffer| taken.push((slot, buffer))),
            2
        );
        assert_eq!(len(&set), 1);

        // The third slot should remain free and be retrievable normally.
        let remaining = set.take().expect("one slot should remain free");
        let mut seen = taken
            .into_iter()
            .map(|(slot, buffer)| {
                drop(buffer);
                slot
            })
            .collect::<Vec<_>>();
        drop(remaining.1);
        seen.push(remaining.0);
        seen.sort_unstable();
        assert_eq!(seen, slots);
        assert!(set.take().is_none());
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
            let set = Arc::new(Freelist::new(NZU32!(1), NZUsize!(1)));
            set.put(0, AlignedBuffer::new(64, 64));

            // Align the contenders so several can race on the same observed
            // word instead of serializing before `take`.
            let barrier = Arc::new(Barrier::new(16));
            let successes = Arc::new(StdAtomicUsize::new(0));
            let mut handles = Vec::new();

            for _ in 0..16 {
                let set = Arc::clone(&set);
                let barrier = Arc::clone(&barrier);
                let successes = Arc::clone(&successes);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    if let Some((_, buffer)) = set.take() {
                        successes.fetch_add(1, AtomicOrdering::Relaxed);
                        drop(buffer);
                    }
                }));
            }

            for handle in handles {
                handle.join().expect("worker should not panic");
            }

            assert_eq!(successes.load(AtomicOrdering::Relaxed), 1);
            assert_eq!(len(&set), 0);
        }
    }

    #[test]
    fn test_freelist_drop_drains_remaining_buffers() {
        // Dropping a non-empty freelist must drop any buffers still parked in
        // globally free slots.
        let set = Freelist::new(NZU32!(2), NZUsize!(2));
        set.put(0, AlignedBuffer::new(64, 64));
        set.put(1, AlignedBuffer::new(64, 64));
        drop(set);
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use loom::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread,
    };
    use std::num::{NonZeroU32, NonZeroUsize};

    // These tests run the production `Freelist` implementation with loom's
    // atomics, thread local storage, and `UnsafeCell` substituted under
    // `cfg(feature = "loom")`. They use two small bitmap geometries: a
    // single-word freelist for same-word RMW races, and a striped freelist for
    // cross-word publication and scan races.
    fn single_word_freelist(capacity: u32) -> Freelist {
        // Use one stripe so every slot in the model shares one bitmap word.
        // This keeps the model small enough for exhaustive exploration while
        // covering the RMW contention that makes this freelist subtle.
        Freelist::new(
            NonZeroU32::new(capacity).unwrap(),
            NonZeroUsize::new(1).unwrap(),
        )
    }

    fn striped_freelist() -> Freelist {
        // Four slots with four stripes puts each modeled slot in a distinct
        // bitmap word. This covers cross-word scan and batch publication without
        // blowing up the model.
        Freelist::new(NonZeroU32::new(4).unwrap(), NonZeroUsize::new(4).unwrap())
    }

    fn buffer() -> AlignedBuffer {
        // The payload itself is not important to the model. The aligned
        // allocation is enough to exercise ownership transfer through the
        // parking cell and make double-reads/double-drops visible.
        AlignedBuffer::new(64, 64)
    }

    #[test]
    fn put_publishes_before_take() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));

            // `put` writes the parking cell before publishing the bit with a
            // Release RMW. The taker spins until it can clear that bit with an
            // Acquire RMW, then reads the same cell.
            //
            // If the publish/claim edge is weakened, loom should be able to
            // schedule the cell read without seeing the prior cell write.
            let writer = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put(0, buffer()))
            };
            let reader = {
                let set = Arc::clone(&set);
                thread::spawn(move || loop {
                    if let Some((slot, buffer)) = set.take() {
                        assert_eq!(slot, 0);
                        drop(buffer);
                        break;
                    }
                    thread::yield_now();
                })
            };

            writer.join().unwrap();
            reader.join().unwrap();
        });
    }

    #[test]
    fn concurrent_puts_merge_disjoint_bits() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));
            let seen = Arc::new(AtomicUsize::new(0));

            // Two producers return different slots that live in the same bitmap
            // word. Their Release `fetch_or` operations must merge the bits:
            // neither producer may overwrite the other's publication.
            //
            // The consumer runs after both producers finish so this test
            // isolates lost producer updates from consumer-side claim races.
            let first = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put(0, buffer()))
            };

            let second = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put(1, buffer()))
            };

            first.join().unwrap();
            second.join().unwrap();

            assert_eq!(
                set.take_batch(2, |slot, buffer| {
                    drop(buffer);
                    let mask = 1 << slot;
                    let previous = seen.fetch_or(mask, Ordering::Relaxed);
                    assert_eq!(previous & mask, 0);
                }),
                2
            );
            assert_eq!(seen.load(Ordering::Relaxed), 0b11);
            assert_eq!(set.drain(), 0);
        });
    }

    #[test]
    fn concurrent_put_batches_merge_disjoint_bits() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(4));
            let seen = Arc::new(AtomicUsize::new(0));

            // Each producer stages two slots and then publishes its per-word
            // mask with one Release `fetch_or`. Because all four slots share a
            // word, this specifically checks that two batch producers merge
            // their masks instead of losing either batch.
            let first = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put_batch([(0, buffer()), (1, buffer())]))
            };

            let second = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put_batch([(2, buffer()), (3, buffer())]))
            };

            first.join().unwrap();
            second.join().unwrap();

            assert_eq!(
                set.take_batch(4, |slot, buffer| {
                    drop(buffer);
                    let mask = 1 << slot;
                    let previous = seen.fetch_or(mask, Ordering::Relaxed);
                    assert_eq!(previous & mask, 0);
                }),
                4
            );
            assert_eq!(seen.load(Ordering::Relaxed), 0b1111);
            assert_eq!(set.drain(), 0);
        });
    }

    #[test]
    fn two_takers_cannot_claim_one_slot() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));
            set.put(0, buffer());

            // Both takers may observe the same relaxed non-zero candidate
            // word. Only one may win the later `fetch_and` claim.
            //
            // This is the minimal stale-candidate case: the relaxed load is
            // allowed to be old, but the returned value from `fetch_and` must
            // decide ownership.
            let successes = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            for _ in 0..2 {
                let set = Arc::clone(&set);
                let successes = Arc::clone(&successes);
                handles.push(thread::spawn(move || {
                    if let Some((slot, buffer)) = set.take() {
                        assert_eq!(slot, 0);
                        drop(buffer);
                        successes.fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(successes.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn batch_claims_survive_intervening_rmw_sequence() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));
            set.put_batch([(0, buffer()), (1, buffer())]);
            let seen = Arc::new(AtomicUsize::new(0));

            // `put_batch` publishes both bits with one Release RMW. This model
            // starts takers after publication to keep the state space small;
            // the writer/reader visibility edge for batch publication is
            // covered by `put_batch_publishes_to_take_batch`.
            //
            // What this case isolates is the two-taker claim sequence on the
            // same word: one taker may clear one bit, then the other taker
            // reads the word through that intervening RMW. Both slots must
            // still be transferred exactly once.
            let mut handles = Vec::new();
            for _ in 0..2 {
                let set = Arc::clone(&set);
                let seen = Arc::clone(&seen);
                handles.push(thread::spawn(move || {
                    if let Some((slot, buffer)) = set.take() {
                        drop(buffer);
                        let mask = 1 << slot;
                        let previous = seen.fetch_or(mask, Ordering::Relaxed);
                        assert_eq!(previous & mask, 0);
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(seen.load(Ordering::Relaxed), 0b11);
        });
    }

    #[test]
    fn take_and_take_batch_do_not_duplicate_slots() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));
            set.put_batch([(0, buffer()), (1, buffer())]);

            // A single-slot claim and a multi-bit claim race on the same word.
            // Each claimed slot is recorded once; any duplicate ownership
            // transfer trips the `previous & mask == 0` assertion.
            //
            // This covers the speculative batch claim path, where `take_batch`
            // first chooses candidate bits and then intersects them with the
            // word value returned by `fetch_and`.
            let seen = Arc::new(AtomicUsize::new(0));
            let batch_count = Arc::new(AtomicUsize::new(0));
            let batch_callbacks = Arc::new(AtomicUsize::new(0));

            let batch_taker = {
                let set = Arc::clone(&set);
                let seen = Arc::clone(&seen);
                let batch_count = Arc::clone(&batch_count);
                let batch_callbacks = Arc::clone(&batch_callbacks);
                thread::spawn(move || {
                    let count = set.take_batch(2, |slot, buffer| {
                        drop(buffer);
                        batch_callbacks.fetch_add(1, Ordering::Relaxed);
                        let mask = 1 << slot;
                        let previous = seen.fetch_or(mask, Ordering::Relaxed);
                        assert_eq!(previous & mask, 0);
                    });
                    batch_count.store(count, Ordering::Relaxed);
                })
            };

            let single_taker = {
                let set = Arc::clone(&set);
                let seen = Arc::clone(&seen);
                thread::spawn(move || {
                    if let Some((slot, buffer)) = set.take() {
                        drop(buffer);
                        let mask = 1 << slot;
                        let previous = seen.fetch_or(mask, Ordering::Relaxed);
                        assert_eq!(previous & mask, 0);
                    }
                })
            };

            batch_taker.join().unwrap();
            single_taker.join().unwrap();

            assert_eq!(seen.load(Ordering::Relaxed), 0b11);
            assert!(batch_count.load(Ordering::Relaxed) <= 2);
            assert_eq!(
                batch_count.load(Ordering::Relaxed),
                batch_callbacks.load(Ordering::Relaxed)
            );
        });
    }

    #[test]
    fn two_take_batches_do_not_duplicate_slots() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));
            set.put_batch([(0, buffer()), (1, buffer())]);

            // Two batch refill paths can speculatively choose the same bits
            // from the relaxed word load. Each callback must still be driven
            // only by bits that caller actually cleared with `fetch_and`.
            let seen = Arc::new(AtomicUsize::new(0));
            let total = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            for _ in 0..2 {
                let set = Arc::clone(&set);
                let seen = Arc::clone(&seen);
                let total = Arc::clone(&total);
                handles.push(thread::spawn(move || {
                    let count = set.take_batch(2, |slot, buffer| {
                        drop(buffer);
                        let mask = 1 << slot;
                        let previous = seen.fetch_or(mask, Ordering::Relaxed);
                        assert_eq!(previous & mask, 0);
                    });
                    total.fetch_add(count, Ordering::Relaxed);
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(seen.load(Ordering::Relaxed), 0b11);
            assert_eq!(total.load(Ordering::Relaxed), 2);
        });
    }

    #[test]
    fn two_take_batches_continue_after_losing_selected_bits() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(3));
            set.put_batch([(0, buffer()), (1, buffer()), (2, buffer())]);

            // Both batch takers can speculatively select the same first two
            // bits from a stale relaxed word load. If one taker clears those
            // bits first, the other must use the word value returned by
            // `fetch_and` and continue on to the still-set third bit instead of
            // stopping after a zero-sized successful claim.
            let seen = Arc::new(AtomicUsize::new(0));
            let total = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            for _ in 0..2 {
                let set = Arc::clone(&set);
                let seen = Arc::clone(&seen);
                let total = Arc::clone(&total);
                handles.push(thread::spawn(move || {
                    let count = set.take_batch(2, |slot, buffer| {
                        drop(buffer);
                        let mask = 1 << slot;
                        let previous = seen.fetch_or(mask, Ordering::Relaxed);
                        assert_eq!(previous & mask, 0);
                    });
                    total.fetch_add(count, Ordering::Relaxed);
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(seen.load(Ordering::Relaxed), 0b111);
            assert_eq!(total.load(Ordering::Relaxed), 3);
            assert_eq!(set.drain(), 0);
        });
    }

    #[test]
    fn put_batch_publishes_to_take_batch() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));
            let seen = Arc::new(AtomicUsize::new(0));

            // This exercises the batch-specific publish and claim path end to
            // end: one Release `fetch_or` makes multiple parked cells visible,
            // and one Acquire `fetch_and` may claim multiple bits.
            //
            // The reader loops because loom may run it before the writer has
            // published anything. A zero-sized claim is just a retry, not an
            // observable failure.
            let writer = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put_batch([(0, buffer()), (1, buffer())]))
            };

            let reader = {
                let set = Arc::clone(&set);
                let seen = Arc::clone(&seen);
                thread::spawn(move || {
                    while seen.load(Ordering::Relaxed) != 0b11 {
                        let claimed = set.take_batch(2, |slot, buffer| {
                            drop(buffer);
                            let mask = 1 << slot;
                            let previous = seen.fetch_or(mask, Ordering::Relaxed);
                            assert_eq!(previous & mask, 0);
                        });

                        if claimed == 0 {
                            thread::yield_now();
                        }
                    }
                })
            };

            writer.join().unwrap();
            reader.join().unwrap();

            assert_eq!(seen.load(Ordering::Relaxed), 0b11);
        });
    }

    #[test]
    fn put_publishes_to_drain() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));
            let drained = Arc::new(AtomicUsize::new(0));

            // `drain` uses an Acquire whole-word swap. Run it concurrently with
            // publication so this model checks the put-side Release edge rather
            // than relying on thread-spawn visibility from pre-populated state.
            //
            // If the swap does not synchronize with the successful put, loom's
            // tracked parking cell can observe the drainer reading the buffer
            // without seeing the writer's earlier cell initialization.
            let writer = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put(0, buffer()))
            };

            let drainer = {
                let set = Arc::clone(&set);
                let drained = Arc::clone(&drained);
                thread::spawn(move || {
                    while drained.load(Ordering::Relaxed) == 0 {
                        let count = set.drain();
                        if count == 0 {
                            // The drainer may run before the writer publishes.
                            // A zero drain is a retry, not a failed assertion.
                            thread::yield_now();
                        } else {
                            assert_eq!(count, 1);
                            drained.store(count, Ordering::Relaxed);
                        }
                    }
                })
            };

            writer.join().unwrap();
            drainer.join().unwrap();

            assert_eq!(drained.load(Ordering::Relaxed), 1);
            assert_eq!(set.drain(), 0);
        });
    }

    #[test]
    fn put_batch_publishes_to_drain() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));
            let drained = Arc::new(AtomicUsize::new(0));

            // A batch publish parks multiple cells before one Release RMW. The
            // drainer loops until its Acquire swap observes that publication and
            // then drops every parked buffer it claimed.
            //
            // This is the drain analogue of `put_batch_publishes_to_take_batch`:
            // the whole-word swap must make all cells represented by the returned
            // word visible before they are dropped.
            let writer = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put_batch([(0, buffer()), (1, buffer())]))
            };

            let drainer = {
                let set = Arc::clone(&set);
                let drained = Arc::clone(&drained);
                thread::spawn(move || {
                    while drained.load(Ordering::Relaxed) < 2 {
                        let count = set.drain();
                        if count == 0 {
                            // The drainer may run before the batch is published.
                            thread::yield_now();
                        } else {
                            assert_eq!(count, 2);
                            let previous = drained.fetch_add(count, Ordering::Relaxed);
                            assert!(previous + count <= 2);
                        }
                    }
                })
            };

            writer.join().unwrap();
            drainer.join().unwrap();

            assert_eq!(drained.load(Ordering::Relaxed), 2);
            assert_eq!(set.drain(), 0);
        });
    }

    #[test]
    fn put_batch_and_take_batch_across_stripes() {
        loom::model(|| {
            let set = Arc::new(striped_freelist());
            let seen = Arc::new(AtomicUsize::new(0));

            // Publish one slot per bitmap word. The reader may observe any
            // prefix of the per-word Release operations and must keep scanning
            // other stripes until it has claimed each slot exactly once.
            //
            // This complements the two-slot same-word models above: same-word
            // tests cover RMW contention on one atomic word, while this checks
            // that the striped scan does not stop after the first word and that
            // each per-word batch publication independently synchronizes with a
            // later claim.
            let writer = {
                let set = Arc::clone(&set);
                thread::spawn(move || {
                    set.put_batch([(0, buffer()), (1, buffer()), (2, buffer()), (3, buffer())])
                })
            };

            let reader = {
                let set = Arc::clone(&set);
                let seen = Arc::clone(&seen);
                thread::spawn(move || {
                    while seen.load(Ordering::Relaxed) != 0b1111 {
                        let claimed = set.take_batch(4, |slot, buffer| {
                            drop(buffer);
                            let mask = 1 << slot;
                            let previous = seen.fetch_or(mask, Ordering::Relaxed);
                            assert_eq!(previous & mask, 0);
                        });

                        if claimed == 0 {
                            thread::yield_now();
                        }
                    }
                })
            };

            writer.join().unwrap();
            reader.join().unwrap();

            assert_eq!(seen.load(Ordering::Relaxed), 0b1111);
            assert_eq!(set.drain(), 0);
        });
    }

    #[test]
    fn put_batch_publishes_to_drain_across_stripes() {
        loom::model(|| {
            let set = Arc::new(striped_freelist());
            let drained = Arc::new(AtomicUsize::new(0));

            // A striped batch publishes one Release `fetch_or` per touched word.
            // The drainer may observe any subset of those per-word publications
            // in one pass, then must keep scanning future passes until every
            // published cell has been acquired and dropped exactly once.
            let writer = {
                let set = Arc::clone(&set);
                thread::spawn(move || {
                    set.put_batch([(0, buffer()), (1, buffer()), (2, buffer()), (3, buffer())])
                })
            };

            let drainer = {
                let set = Arc::clone(&set);
                let drained = Arc::clone(&drained);
                thread::spawn(move || {
                    while drained.load(Ordering::Relaxed) < 4 {
                        let count = set.drain();
                        if count == 0 {
                            // The drainer may run before the writer has
                            // published another stripe.
                            thread::yield_now();
                        } else {
                            let previous = drained.fetch_add(count, Ordering::Relaxed);
                            assert!(previous + count <= 4);
                        }
                    }
                })
            };

            writer.join().unwrap();
            drainer.join().unwrap();

            assert_eq!(drained.load(Ordering::Relaxed), 4);
            assert_eq!(set.drain(), 0);
        });
    }

    #[test]
    fn drain_and_take_do_not_duplicate_or_lose_slots() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));
            set.put_batch([(0, buffer()), (1, buffer())]);

            let drained = Arc::new(AtomicUsize::new(0));
            let taken = Arc::new(AtomicUsize::new(0));

            // `drain` clears a whole word with `swap(0)` while `take` clears
            // one bit with `fetch_and`. Racing them should transfer ownership
            // of each parked buffer exactly once and leave no free bits behind.
            //
            // This also covers the synchronization shape used by `Drop`, which
            // drains any buffers that remain globally free.
            let drainer = {
                let set = Arc::clone(&set);
                let drained = Arc::clone(&drained);
                thread::spawn(move || {
                    drained.store(set.drain(), Ordering::Relaxed);
                })
            };

            let taker = {
                let set = Arc::clone(&set);
                let taken = Arc::clone(&taken);
                thread::spawn(move || {
                    if let Some((_slot, buffer)) = set.take() {
                        drop(buffer);
                        taken.store(1, Ordering::Relaxed);
                    }
                })
            };

            drainer.join().unwrap();
            taker.join().unwrap();

            assert_eq!(set.drain(), 0);
            assert_eq!(
                drained.load(Ordering::Relaxed) + taken.load(Ordering::Relaxed),
                2
            );
        });
    }

    #[test]
    fn two_drains_do_not_duplicate_or_lose_slots() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));
            set.put_batch([(0, buffer()), (1, buffer())]);

            let total = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            // `drain` is a public whole-word `swap(0)` operation. Two drainers
            // racing on the same word must split ownership according to the
            // values returned by their swaps: one may drain both slots and the
            // other none, but the total must be exactly the original occupancy.
            for _ in 0..2 {
                let set = Arc::clone(&set);
                let total = Arc::clone(&total);
                handles.push(thread::spawn(move || {
                    total.fetch_add(set.drain(), Ordering::Relaxed);
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            assert_eq!(total.load(Ordering::Relaxed), 2);
            assert_eq!(set.drain(), 0);
        });
    }

    #[test]
    fn drain_and_take_batch_do_not_duplicate_or_lose_slots() {
        loom::model(|| {
            let set = Arc::new(single_word_freelist(2));
            set.put_batch([(0, buffer()), (1, buffer())]);

            let drained = Arc::new(AtomicUsize::new(0));
            let taken = Arc::new(AtomicUsize::new(0));

            // This is the same whole-word `swap(0)` race as the single-slot
            // drain test, but the competing operation clears a speculative
            // multi-bit claim. It makes sure `take_batch` uses the word value
            // returned by `fetch_and`, not just the earlier relaxed load.
            let drainer = {
                let set = Arc::clone(&set);
                let drained = Arc::clone(&drained);
                thread::spawn(move || {
                    drained.store(set.drain(), Ordering::Relaxed);
                })
            };

            let batch_taker = {
                let set = Arc::clone(&set);
                let taken = Arc::clone(&taken);
                thread::spawn(move || {
                    let count = set.take_batch(2, |_slot, buffer| {
                        drop(buffer);
                    });
                    taken.store(count, Ordering::Relaxed);
                })
            };

            drainer.join().unwrap();
            batch_taker.join().unwrap();

            assert_eq!(set.drain(), 0);
            assert_eq!(
                drained.load(Ordering::Relaxed) + taken.load(Ordering::Relaxed),
                2
            );
        });
    }
}
