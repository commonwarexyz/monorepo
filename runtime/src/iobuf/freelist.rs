//! Striped global freelist for one buffer-pool size class.
//!
//! A [`Freelist`] belongs to one [`super::pool::BufferPool`] size class. Each
//! tracked buffer in that class has a stable slot id. When the buffer is not
//! checked out or held in a thread-local cache, the freelist owns that slot and
//! makes it available for reuse by any thread.
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
//! Free bits are split across cache-line-padded atomic words. Consecutive slot
//! ids are not packed into the same word. Instead low slot-id bits choose the
//! word and high slot-id bits choose the bit inside that word. With eight words,
//! slots 0..7 occupy bit 0 in different words, slots 8..15 occupy bit 1 in
//! those same words, and so on. This gives concurrent threads more independent
//! atomic words to target without changing the slot ids handed back to the pool.
//!
//! With a power-of-two word count, the mapping is:
//!
//! - `word = slot & word_mask`
//! - `bit = slot >> word_shift`
//!
//! The pool passes its expected parallelism so the freelist can match the
//! bitmap width to the expected contention level. The freelist rounds that
//! target up to a power of two and caps it at the largest power of two that can
//! fit within capacity, so striping does not create words that can never contain
//! a slot. Larger capacities may still use more words so no bitmap word tracks
//! more than 64 slots.
//!
//! The hot paths are fast for a few concrete reasons:
//!
//! - `put` is just "write buffer into the parking cell, then `fetch_or` one bit".
//! - `take` uses a stable per-thread home word before scanning others, so
//!   threads tend to start from different stripes.
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
    cell::UnsafeCell,
    mem::MaybeUninit,
    num::{NonZeroU32, NonZeroUsize},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

/// Number of slot bits tracked in each bitmap word.
const SLOT_BITMAP_WORD_BITS: usize = u64::BITS as usize;
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
    /// steady state. Without padding, adjacent words can still fight over the
    /// same cache line even when they represent disjoint slot stripes.
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

        let put_entries = |masks: &mut [u64]| {
            // Masks are staged by word after parking the buffers. The later
            // Release `fetch_or` makes every staged slot in that word available.
            for (slot, buffer) in [(slot, buffer), (next_slot, next_buffer)]
                .into_iter()
                .chain(entries)
            {
                // Park first, then stage the bit for the later per-word publish.
                self.park(slot, buffer);
                let (word_index, mask) = self.slot_word(slot);
                masks[word_index] |= mask;
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
        };

        let word_count = self.words.len();
        if word_count <= INLINE_PUT_BATCH_MASKS {
            let mut masks = [0u64; INLINE_PUT_BATCH_MASKS];
            put_entries(&mut masks[..word_count]);
        } else {
            // Very large freelists are uncommon, so keep the common case on the
            // stack and fall back to heap scratch only when the bitmap is wider
            // than the fixed inline staging area.
            let mut masks = vec![0u64; word_count];
            put_entries(masks.as_mut_slice());
        }
    }

    /// Takes any one free slot from the global freelist.
    ///
    /// On success, ownership of the returned slot is transferred to the caller.
    ///
    /// The search starts from a stable per-thread home word and scans the other
    /// stripes only on miss. Within a word, `fetch_and` claims one bit. That is
    /// important: unlike a full-word CAS loop, two threads removing different
    /// bits from the same word can both succeed.
    #[inline]
    pub fn take(&self) -> Option<(u32, AlignedBuffer)> {
        let thread_id = SlotBitmapProbe::thread_id();
        let start_word = thread_id & self.word_mask;
        let bit_offset = ((thread_id >> self.word_shift) & (SLOT_BITMAP_WORD_BITS - 1)) as u32;

        for scanned in 0..self.words.len() {
            let word_index = (start_word + scanned) & self.word_mask;
            let word_ref = &self.words[word_index];
            // This load only finds candidate bits. The `fetch_and` below is the
            // operation that claims a bit and acquires the matching parked
            // buffer.
            let mut word = word_ref.load(Ordering::Relaxed);

            while word != 0 {
                // Probe a thread-specific bit order inside the chosen word so
                // colliding threads do not all stampede bit 0 first.
                let bit = SlotBitmapProbe::select_set_bit(word, bit_offset);
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

    /// Takes up to `max` free slots from the global freelist.
    ///
    /// Ownership of each claimed slot is transferred to `put_entry`.
    ///
    /// `put_entry` receives each claimed `(slot, buffer)` pair. This avoids
    /// internal allocation and lets callers fill an existing spill/refill
    /// buffer directly. `put_entry` must not panic: for batch claims, bits are
    /// cleared before buffers are handed to the callback, so a panic could strand
    /// already-claimed slots outside the freelist.
    ///
    /// For `max > 1`, the implementation tries to claim several bits from the
    /// same word in a single atomic `fetch_and`, which amortizes the shared
    /// synchronization cost across the batch.
    #[inline]
    pub fn take_batch(&self, max: usize, mut put_entry: impl FnMut(u32, AlignedBuffer)) -> usize {
        if max == 1 {
            let Some((slot, buffer)) = self.take() else {
                return 0;
            };
            put_entry(slot, buffer);
            return 1;
        }

        let thread_id = SlotBitmapProbe::thread_id();
        let start_word = thread_id & self.word_mask;
        let bit_offset = ((thread_id >> self.word_shift) & (SLOT_BITMAP_WORD_BITS - 1)) as u32;
        let mut filled = 0;

        for scanned in 0..self.words.len() {
            if filled == max {
                break;
            }

            let word_index = (start_word + scanned) & self.word_mask;
            let word_ref = &self.words[word_index];
            // As in `take`, this relaxed load only chooses candidate bits. The
            // Acquire `fetch_and` below claims whichever candidates are still
            // present.
            let mut word = word_ref.load(Ordering::Relaxed);

            while word != 0 && filled < max {
                // Stage several candidate bits from the current word, then try
                // to clear all of them with one atomic operation.
                let claim = SlotBitmapProbe::select_set_bits(word, bit_offset, max - filled);
                let observed = word_ref.fetch_and(!claim, Ordering::Acquire);
                // `claim` is speculative. Intersect it with the observed word
                // to keep only the bits this thread actually cleared.
                let mut claimed = observed & claim;

                while claimed != 0 {
                    let bit = SlotBitmapProbe::select_set_bit(claimed, bit_offset);
                    let slot = self.slot_index(word_index, bit);
                    // These bits were cleared by the Acquire `fetch_and`
                    // above, so each corresponding parked buffer is now owned
                    // by this caller.
                    put_entry(slot, self.unpark(slot));
                    claimed &= !(1u64 << bit);
                    filled += 1;
                }

                // Continue from the word snapshot returned by `fetch_and`.
                word = observed & !claim;
            }
        }

        filled
    }

    /// Parks a buffer in the storage cell for a slot outside the freelist.
    ///
    /// The caller must own `slot` and mark the corresponding bit only after
    /// this write completes.
    #[inline(always)]
    fn park(&self, slot: u32, buffer: AlignedBuffer) {
        // SAFETY: the caller owns this slot while it is outside the freelist, so no
        // other thread can access the parking cell until the slot bit is set.
        unsafe {
            (*self
                .storage
                .get(slot as usize)
                .expect("slot id must refer to an allocated slot")
                .get())
            .write(buffer);
        }
    }

    /// Removes the parked buffer from a slot whose free bit was just claimed.
    ///
    /// The caller must have cleared the slot's bit before reading the cell.
    #[inline(always)]
    fn unpark(&self, slot: u32) -> AlignedBuffer {
        // SAFETY: a successful bit clear removes this slot from the free set,
        // so we have exclusive access to the initialized buffer that was
        // made available by the matching put.
        unsafe {
            (*self
                .storage
                .get(slot as usize)
                .expect("slot id must refer to an allocated slot")
                .get())
            .assume_init_read()
        }
    }
}

impl Drop for Freelist {
    fn drop(&mut self) {
        // Any slot still free in the freelist owns an initialized parked
        // buffer in its parking cell. Drain them explicitly so the underlying
        // aligned allocations are released before the raw storage backing the
        // freelist itself goes away.
        while let Some((_, buffer)) = self.take() {
            drop(buffer);
        }
    }
}

/// Helper facade for per-thread probe state and per-word bit selection.
///
/// Keeping this logic in one place makes the claim path easier to read and
/// keeps the freelist API focused on putting and taking slots.
struct SlotBitmapProbe;

static NEXT_SLOT_BITMAP_THREAD_ID: AtomicUsize = AtomicUsize::new(0);

impl SlotBitmapProbe {
    thread_local! {
        // Assign each thread a stable numeric id on first touch so its home
        // word selection is deterministic instead of depending on thread-local
        // storage layout.
        // Relaxed ordering is enough: these ids only spread probes out and do
        // not synchronize access to buffers.
        static TLS_SLOT_BITMAP_THREAD_ID: usize =
            NEXT_SLOT_BITMAP_THREAD_ID.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn thread_id() -> usize {
        Self::TLS_SLOT_BITMAP_THREAD_ID.with(|thread_id| *thread_id)
    }

    #[inline]
    fn select_set_bit(word: u64, bit_offset: u32) -> usize {
        debug_assert_ne!(word, 0);
        // Rotate the word so the thread's preferred probe offset becomes bit 0,
        // select the first set bit in that rotated view, then rotate the answer
        // back into the original word numbering.
        let rotated = word.rotate_right(bit_offset);
        ((rotated.trailing_zeros() + bit_offset) & (SLOT_BITMAP_WORD_BITS as u32 - 1)) as usize
    }

    #[inline]
    fn select_set_bits(word: u64, bit_offset: u32, limit: usize) -> u64 {
        debug_assert_ne!(word, 0);
        debug_assert!(limit > 0);

        // Gather up to `limit` set bits using the same rotated probe order as
        // `select_set_bit`. The result is rotated back so callers can apply it
        // directly as a mask against the original word.
        let mut remaining = word.rotate_right(bit_offset);
        let mut selected = 0u64;
        let mut taken = 0;

        while remaining != 0 && taken < limit {
            let bit = remaining.trailing_zeros();
            let mask = 1u64 << bit;
            selected |= mask;
            remaining &= !mask;
            taken += 1;
        }

        selected.rotate_left(bit_offset)
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

    /// Returns the current number of free slots.
    ///
    /// This count is intentionally derived on demand rather than maintained on
    /// the hot path, because a contended global length counter would add an
    /// extra atomic read-modify-write to every `put` and `take`.
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
        set.put_batch(std::iter::empty());
        assert_eq!(len(&set), 0);

        // A single-entry batch delegates to `put`, preserving the cheaper
        // one-buffer path.
        set.put_batch([(3, AlignedBuffer::new(64, 64))]);
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
        set.put_batch(
            [1u32, 5, 7]
                .into_iter()
                .map(|slot| (slot, AlignedBuffer::new(64, 64))),
        );
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

        set.put_batch(
            [0u32, 1, 64, 4096]
                .into_iter()
                .map(|slot| (slot, AlignedBuffer::new(64, 64))),
        );
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
        assert_eq!(slots, vec![0, 1, 64, 4096]);
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
        // `max == 0` must return immediately and must not call the callback.
        assert_eq!(
            set.take_batch(0, |_, _| panic!(
                "take_batch should not have produced an entry"
            )),
            0
        );
        assert!(taken.is_empty());

        // `max == 1` intentionally uses the single-slot `take` path.
        assert_eq!(
            set.take_batch(1, |slot, buffer| taken.push((slot, buffer))),
            1
        );
        assert_eq!(taken.len(), 1);

        // A request larger than the remaining occupancy should return only the
        // slots that were actually available.
        assert_eq!(
            set.take_batch(8, |slot, buffer| taken.push((slot, buffer))),
            2
        );
        assert_eq!(taken.len(), 3);
        // Once empty, neither the batch nor single path may invoke the callback.
        assert_eq!(
            set.take_batch(8, |_, _| panic!(
                "take_batch should not have produced an entry"
            )),
            0
        );
        assert_eq!(
            set.take_batch(1, |_, _| panic!(
                "take_batch should not have produced an entry"
            )),
            0
        );

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
        let start_word = SlotBitmapProbe::thread_id() & set.word_mask;
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
        let start_word = SlotBitmapProbe::thread_id() & set.word_mask;
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

        assert_eq!(SlotBitmapProbe::select_set_bit(word, 0), 1);
        assert_eq!(SlotBitmapProbe::select_set_bit(word, 6), 9);

        let selected = SlotBitmapProbe::select_set_bits(word, 6, 2);
        // Starting after bit 6, the first two set bits are 9 and 20.
        assert_eq!(selected.count_ones(), 2);
        assert_eq!(selected & !word, 0);
        assert_eq!(selected, (1u64 << 9) | (1u64 << 20));
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
