//! Lock-free striped freelist for tracked buffer slots.
//!
//! [`Freelist`] is the shared fallback path behind [`super::pool::BufferPool`]'s
//! thread-local caches. The local caches handle the common case cheaply inside a
//! thread. When a cache needs to refill or spill, it exchanges tracked buffers
//! with this module by slot id.
//!
//! The freelist is intentionally specialized for that environment:
//!
//! - Capacity is fixed when the size class is created.
//! - Every tracked buffer already has a stable slot id.
//! - The global structure only needs "take any free slot" semantics.
//! - Refill and spill naturally batch work.
//!
//! That lets the implementation avoid a general MPMC queue. Instead, free
//! slots live in a striped bitmap:
//!
//! - `storage[slot]` parks the actual [`AlignedBuffer`] for that slot.
//! - `words[word_index]` tracks which slots mapped to that stripe are free.
//! - Setting a bit publishes a returned buffer.
//! - Clearing a bit claims a free slot.
//!
//! Slot ids are striped across words rather than packed densely into one word.
//! With a power-of-two word count, the mapping is:
//!
//! - `word = slot & word_mask`
//! - `bit = slot >> word_shift`
//!
//! This deliberately spends extra bitmap words to improve scalability. Small
//! freelists can still spread threads across several cache lines, instead of
//! collapsing all contention onto one `AtomicU64`.
//!
//! The hot paths are fast for a few concrete reasons:
//!
//! - `put` is just "write buffer into slot storage, then `fetch_or` one bit".
//! - `take` uses a stable per-thread home word before scanning others, so
//!   threads tend to start from different stripes.
//! - `take` claims bits with `fetch_and` instead of a CAS loop. Two threads
//!   removing different bits from the same word can both succeed without one
//!   having to restart from scratch.
//! - `put_batch` coalesces returned slots per word, turning many logical
//!   inserts into one atomic `fetch_or` per touched stripe.
//! - `take_batch` claims several bits from one word with one atomic operation,
//!   which matches the refill behavior of the thread-local caches.
//!
//! The implementation is lock-free for the shared bitmap operations, but it is
//! not a standalone general-purpose container. It relies on BufferPool's slot
//! ownership discipline: while a buffer is checked out or sitting in a thread's
//! local cache, that slot id is exclusively owned by that thread and therefore
//! absent from the bitmap.
//!
//! [`super::pool::BufferPool`]: super::pool::BufferPool
use super::aligned::AlignedBuffer;
use crossbeam_utils::CachePadded;
use std::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

/// Number of slot bits tracked in each bitmap word.
const SLOT_BITMAP_WORD_BITS: usize = u64::BITS as usize;
/// Number of word masks stored on the stack before falling back to heap scratch.
const INLINE_PUT_BATCH_MASKS: usize = 64;

/// Bounded lock-free freelist of slot ids for one size class.
///
/// Each tracked buffer has a stable slot id. A slot is either:
///
/// - owned by a checked-out buffer,
/// - parked in a thread-local cache, or
/// - published in this freelist.
///
/// Publishing stores the buffer into its slot storage cell and sets the
/// corresponding free bit. Taking a slot clears a free bit and reads the
/// initialized buffer back out of that slot storage cell.
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
    /// buffer into storage before setting the bit, and `take` clears the bit
    /// before reading the buffer back out.
    storage: Box<[UnsafeCell<MaybeUninit<AlignedBuffer>>]>,
    /// Mask used to map a slot id to its striped bitmap word.
    word_mask: usize,
    /// Number of low slot-id bits consumed by the word index.
    word_shift: u32,
}

// SAFETY: slot storage cells are only accessed by the thread that currently
// owns their slot id. Publication and removal from the global free set are
// synchronized via bitmap bit transitions.
unsafe impl Send for Freelist {}
// SAFETY: see above.
unsafe impl Sync for Freelist {}

impl Freelist {
    /// Creates a new fixed-capacity freelist.
    ///
    /// `preferred_words` is a scalability hint, not an exact size. The freelist
    /// will use at least enough words to represent every slot, and may use more
    /// words to spread contention across cache lines for small capacities.
    pub fn new(capacity: usize, preferred_words: usize) -> Self {
        assert!(capacity > 0, "freelist capacity must be non-zero");
        assert!(
            preferred_words > 0,
            "freelist preferred word count must be non-zero"
        );

        let word_count = Self::word_count(capacity, preferred_words);
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

    #[inline]
    fn word_count(capacity: usize, preferred_words: usize) -> usize {
        // Small freelists still reserve several striped words so different
        // threads can start from different cache lines. Large freelists are
        // constrained by the number of bits required to represent all slots.
        let striped_floor = preferred_words.min(capacity.next_power_of_two());
        striped_floor
            .max(capacity.div_ceil(SLOT_BITMAP_WORD_BITS))
            .next_power_of_two()
    }

    #[inline]
    fn slot_word(&self, slot: u32) -> (usize, u64) {
        let slot = slot as usize;
        // Stripe slot ids across words instead of packing them contiguously into
        // one word. For example with 8 words, slots 0..7 occupy bit 0 of
        // different words, slots 8..15 occupy bit 1 of those same words, and so
        // on. This gives small capacities more opportunities to avoid
        // same-word contention.
        let word_index = slot & self.word_mask;
        let bit = slot >> self.word_shift;
        debug_assert!(bit < SLOT_BITMAP_WORD_BITS);
        (word_index, 1u64 << bit)
    }

    #[inline]
    fn slot_index(&self, word_index: usize, bit: usize) -> u32 {
        // Inverse of `slot_word`.
        let slot = (bit << self.word_shift) | word_index;
        debug_assert!(slot < self.storage.len());
        slot as u32
    }

    /// Returns the current number of free slots for tests and debug assertions.
    ///
    /// This count is intentionally derived on demand rather than maintained on
    /// the hot path, because a contended global length counter would add an
    /// extra atomic RMW to every `put` and `take`.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.load(Ordering::Acquire).count_ones() as usize)
            .sum()
    }

    #[cfg(test)]
    #[inline]
    pub(super) fn num_words(&self) -> usize {
        self.words.len()
    }

    /// Publishes one tracked buffer into the global freelist.
    ///
    /// The buffer is first written back into slot storage, then the slot's free
    /// bit is set with `Release` ordering. A successful `take` performs the
    /// matching `Acquire` operation before reading the buffer back out.
    #[inline]
    pub fn put(&self, slot: u32, buffer: AlignedBuffer) {
        // SAFETY: the caller owns this slot id while it is off-set, so no
        // other thread can access the slot storage until the slot bit is set.
        unsafe {
            (*self.storage(slot).get()).write(buffer);
        }

        let (word_index, mask) = self.slot_word(slot);
        let previous = self.words[word_index].fetch_or(mask, Ordering::Release);
        debug_assert_eq!(
            previous & mask,
            0,
            "returned slot must not already be marked free"
        );
    }

    /// Publishes several tracked buffers into the global freelist.
    ///
    /// Batch insertion groups returned slots by bitmap word so each touched
    /// stripe needs only one atomic `fetch_or`, regardless of how many entries
    /// in the batch map to that word.
    pub fn put_batch(&self, entries: impl IntoIterator<Item = (u32, AlignedBuffer)>) {
        let mut entries = entries.into_iter();
        self.put_batch_iter(&mut entries);
    }

    /// Takes any one free slot from the global freelist.
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
            let mut word = word_ref.load(Ordering::Relaxed);

            while word != 0 {
                // Probe a thread-specific bit order inside the chosen word so
                // colliding threads do not all stampede bit 0 first.
                let bit = SlotBitmapProbe::select_set_bit(word, bit_offset);
                let mask = 1u64 << bit;
                let observed = word_ref.fetch_and(!mask, Ordering::Acquire);
                if observed & mask != 0 {
                    let slot = self.slot_index(word_index, bit);
                    // SAFETY: a successful bit clear removes this slot from
                    // the free set, so we now have exclusive access to the
                    // initialized buffer that was published by the matching
                    // put.
                    let buffer = unsafe { (*self.storage(slot).get()).assume_init_read() };
                    return Some((slot, buffer));
                }

                // Another thread removed that bit first. Reuse the returned word
                // value instead of restarting the whole scan from the beginning.
                word = observed & !mask;
            }
        }

        None
    }

    /// Takes up to `max` free slots from the global freelist.
    ///
    /// `put_entry` receives each claimed `(slot, buffer)` pair. This avoids
    /// internal allocation and lets callers fill an existing spill/refill
    /// buffer directly.
    ///
    /// For `max > 1`, the implementation tries to claim several bits from the
    /// same word in a single atomic `fetch_and`, which amortizes the shared
    /// synchronization cost across the batch.
    pub fn take_batch(&self, max: usize, mut put_entry: impl FnMut(u32, AlignedBuffer)) -> usize {
        self.take_batch_with(max, &mut put_entry)
    }

    fn put_batch_iter(&self, entries: &mut dyn Iterator<Item = (u32, AlignedBuffer)>) {
        let Some((slot, buffer)) = entries.next() else {
            return;
        };
        let Some((next_slot, next_buffer)) = entries.next() else {
            self.put(slot, buffer);
            return;
        };

        let mut inline_masks = [0u64; INLINE_PUT_BATCH_MASKS];
        let mut heap_masks = Vec::new();
        let masks = if self.words.len() <= INLINE_PUT_BATCH_MASKS {
            &mut inline_masks[..self.words.len()]
        } else {
            // Very large freelists are uncommon, so keep the common case on the
            // stack and fall back to heap scratch only when the bitmap is wider
            // than the fixed inline staging area.
            heap_masks.resize(self.words.len(), 0);
            heap_masks.as_mut_slice()
        };

        for (slot, buffer) in [(slot, buffer), (next_slot, next_buffer)] {
            // SAFETY: the caller owns this slot id while it is off-set, so no
            // other thread can access the slot storage until the slot bit is set.
            unsafe {
                (*self.storage(slot).get()).write(buffer);
            }

            let (word_index, mask) = self.slot_word(slot);
            masks[word_index] |= mask;
        }

        for (slot, buffer) in entries {
            // SAFETY: the caller owns this slot id while it is off-set, so no
            // other thread can access the slot storage until the slot bit is set.
            unsafe {
                (*self.storage(slot).get()).write(buffer);
            }

            let (word_index, mask) = self.slot_word(slot);
            masks[word_index] |= mask;
        }

        for (word_index, &mask) in masks.iter().enumerate() {
            if mask == 0 {
                continue;
            }

            // One atomic `fetch_or` publishes every slot in this word-sized
            // subset of the batch.
            let previous = self.words[word_index].fetch_or(mask, Ordering::Release);
            debug_assert_eq!(
                previous & mask,
                0,
                "returned slot batch must not already contain a free slot"
            );
        }
    }

    fn take_batch_with(&self, max: usize, put_entry: &mut dyn FnMut(u32, AlignedBuffer)) -> usize {
        match max {
            0 => return 0,
            1 => {
                let Some((slot, buffer)) = self.take() else {
                    return 0;
                };
                put_entry(slot, buffer);
                return 1;
            }
            _ => {}
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
            let mut word = word_ref.load(Ordering::Relaxed);

            while word != 0 && filled < max {
                // Stage several candidate bits from the current word, then try
                // to clear all of them with one atomic operation.
                let claim = SlotBitmapProbe::select_set_bits(word, bit_offset, max - filled);
                let observed = word_ref.fetch_and(!claim, Ordering::Acquire);
                let mut claimed = observed & claim;

                while claimed != 0 {
                    let bit = SlotBitmapProbe::select_set_bit(claimed, bit_offset);
                    let slot = self.slot_index(word_index, bit);
                    // SAFETY: the cleared bit removed this slot from the free
                    // set, so we now have exclusive access to the initialized
                    // buffer published by the matching put.
                    let buffer = unsafe { (*self.storage(slot).get()).assume_init_read() };
                    put_entry(slot, buffer);
                    claimed &= !(1u64 << bit);
                    filled += 1;
                }

                // Continue from the word snapshot returned by `fetch_and`.
                word = observed & !claim;
            }
        }

        filled
    }

    #[inline]
    fn storage(&self, slot: u32) -> &UnsafeCell<MaybeUninit<AlignedBuffer>> {
        self.storage
            .get(slot as usize)
            .expect("slot id must refer to an allocated slot")
    }
}

impl Drop for Freelist {
    fn drop(&mut self) {
        // Any slot still published in the freelist owns an initialized parked
        // buffer in `storage`. Drain them explicitly so the underlying aligned
        // allocations are released before the raw storage backing the freelist
        // itself goes away.
        while let Some((_, buffer)) = self.take() {
            drop(buffer);
        }
    }
}

/// Helper facade for per-thread probe state and per-word bit selection.
///
/// Keeping this logic in one place makes the claim path easier to read and
/// keeps the freelist API focused on slot publication and removal.
struct SlotBitmapProbe;

static NEXT_SLOT_BITMAP_THREAD_ID: AtomicUsize = AtomicUsize::new(0);

impl SlotBitmapProbe {
    thread_local! {
        // Assign each thread a stable numeric id on first touch so its home
        // word selection is deterministic instead of depending on TLS layout.
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
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize as StdAtomicUsize, Ordering as AtomicOrdering},
        Arc, Barrier,
    };

    fn unexpected_entry(_: u32, _: AlignedBuffer) {
        panic!("take_batch should not have produced an entry");
    }

    #[test]
    #[should_panic(expected = "take_batch should not have produced an entry")]
    fn test_unexpected_entry_panics() {
        unexpected_entry(0, AlignedBuffer::new(64, 64));
    }

    #[test]
    fn test_freelist_returns_each_slot_once() {
        let set = Freelist::new(3, 8);

        for slot in 0..3 {
            set.put(slot, AlignedBuffer::new(64, 64));
        }

        let mut seen = [false; 3];
        for _ in 0..3 {
            let (slot, buffer) = set.take().expect("slot should be available");
            assert!(!seen[slot as usize]);
            seen[slot as usize] = true;
            drop(buffer);
        }

        assert_eq!(set.len(), 0);
        assert!(seen.into_iter().all(|seen| seen));
        assert!(set.take().is_none());
    }

    #[test]
    fn test_freelist_uses_striped_power_of_two_words() {
        let cases = [
            (1, 1),
            (2, 2),
            (3, 4),
            (16, 8),
            (64, 8),
            (512, 8),
            (513, 16),
            (4097, 128),
        ];

        for (capacity, expected_words) in cases {
            let set = Freelist::new(capacity, 8);
            assert_eq!(set.num_words(), expected_words);
            assert!(set.num_words().is_power_of_two());

            for slot in 0..capacity {
                let (word_index, mask) = set.slot_word(slot as u32);
                let bit = mask.trailing_zeros() as usize;
                assert!(word_index < expected_words);
                assert_eq!(set.slot_index(word_index, bit), slot as u32);
            }
        }
    }

    #[test]
    fn test_freelist_put_batch_handles_empty_single_and_multi_entry_paths() {
        let set = Freelist::new(8, 8);

        set.put_batch(std::iter::empty());
        assert_eq!(set.len(), 0);

        set.put_batch([(3, AlignedBuffer::new(64, 64))]);
        assert_eq!(set.len(), 1);

        let mut taken = Vec::new();
        assert_eq!(
            set.take_batch(1, |slot, buffer| taken.push((slot, buffer))),
            1
        );
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].0, 3);
        taken.clear();

        set.put_batch(
            [1u32, 5, 7]
                .into_iter()
                .map(|slot| (slot, AlignedBuffer::new(64, 64))),
        );
        assert_eq!(set.len(), 3);

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
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_freelist_put_batch_uses_heap_masks_when_word_count_exceeds_inline_capacity() {
        let set = Freelist::new(4097, 65);
        assert!(set.num_words() > INLINE_PUT_BATCH_MASKS);

        set.put_batch(
            [0u32, 1, 64, 4096]
                .into_iter()
                .map(|slot| (slot, AlignedBuffer::new(64, 64))),
        );
        assert_eq!(set.len(), 4);

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
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_freelist_take_batch_handles_zero_single_and_partial_fill() {
        let set = Freelist::new(4, 8);
        for slot in 0..3 {
            set.put(slot, AlignedBuffer::new(64, 64));
        }

        let mut taken = Vec::new();
        assert_eq!(set.take_batch(0, unexpected_entry), 0);
        assert!(taken.is_empty());

        assert_eq!(
            set.take_batch(1, |slot, buffer| taken.push((slot, buffer))),
            1
        );
        assert_eq!(taken.len(), 1);

        assert_eq!(
            set.take_batch(8, |slot, buffer| taken.push((slot, buffer))),
            2
        );
        assert_eq!(taken.len(), 3);
        assert_eq!(set.take_batch(8, unexpected_entry), 0);
        assert_eq!(set.take_batch(1, unexpected_entry), 0);

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
        let set = Freelist::new(16, 8);
        let start_word = SlotBitmapProbe::thread_id() & set.word_mask;
        let slot0 = set.slot_index(start_word, 0);
        let slot1 = set.slot_index(start_word, 1);

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
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_freelist_take_batch_stops_mid_word_when_limit_is_reached() {
        let set = Freelist::new(24, 8);
        let start_word = SlotBitmapProbe::thread_id() & set.word_mask;
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
        assert_eq!(set.len(), 1);

        let remaining = set.take().expect("one slot should remain published");
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
        let word = (1u64 << 1) | (1u64 << 5) | (1u64 << 9) | (1u64 << 20);

        assert_eq!(SlotBitmapProbe::select_set_bit(word, 0), 1);
        assert_eq!(SlotBitmapProbe::select_set_bit(word, 6), 9);

        let selected = SlotBitmapProbe::select_set_bits(word, 6, 2);
        assert_eq!(selected.count_ones(), 2);
        assert_eq!(selected & !word, 0);
        assert_eq!(selected, (1u64 << 9) | (1u64 << 20));
    }

    #[test]
    fn test_freelist_take_retries_after_losing_a_same_bit_race() {
        // Force repeated same-word contention on a single published slot. Some
        // contenders should observe a stale non-zero word and follow the retry
        // path before discovering that another thread already claimed the slot.
        for _ in 0..32 {
            let set = Arc::new(Freelist::new(1, 1));
            set.put(0, AlignedBuffer::new(64, 64));

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
            assert_eq!(set.len(), 0);
        }
    }

    #[test]
    fn test_freelist_drop_drains_remaining_buffers() {
        let set = Freelist::new(2, 8);
        set.put(0, AlignedBuffer::new(64, 64));
        set.put(1, AlignedBuffer::new(64, 64));
        drop(set);
    }
}
