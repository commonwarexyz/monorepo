//! Striped global freelist for one buffer-pool size class.
//!
//! Stable slots are partitioned across cache-isolated stripes. Each stripe owns
//! packed authoritative leaf bits, stable owner records, and one advisory state
//! word that bounds empty searches. Lazy creation uses a separate monotonic
//! cursor per stripe and preserves the same probe phases used for reuse.
//!
//! A set leaf bit exclusively owns its buffer. Summary state only navigates to
//! leaves and may be stale. Returns publish leaves before summaries, while
//! takes acquire leaf ownership before rebuilding a [`PooledBuffer`]. Drain and
//! drop ignore summaries and reclaim directly from the authoritative leaves.

use super::owner::{PooledBuffer, PooledOwner};
use crossbeam_utils::CachePadded;
use std::{
    alloc::Layout,
    cell::Cell,
    mem::{MaybeUninit, size_of},
    num::{NonZeroU32, NonZeroUsize},
    ptr, slice,
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

const SLOT_WORD_BITS: usize = u64::BITS as usize;
const SLOT_WORD_SHIFT: u32 = SLOT_WORD_BITS.trailing_zeros();
const MAX_FREELIST_STRIPES: usize = 4096;
const TARGET_MAX_SLOTS_PER_STRIPE: usize = 1 << 24;
const AVAILABILITY_BITS: usize = 58;
const CODE_SHIFT: u32 = AVAILABILITY_BITS as u32;
const AVAILABILITY_MASK: u64 = (1u64 << CODE_SHIFT) - 1;
const CODE_MASK: u64 = !AVAILABILITY_MASK;
const CURSOR_NEXT_BITS: u32 = 25;
const CURSOR_NEXT_MASK: u64 = (1u64 << CURSOR_NEXT_BITS) - 1;
const PROBE_PHASE_BITS: u32 = 39;
const PROBE_PHASE_MASK: u64 = (1u64 << PROBE_PHASE_BITS) - 1;
const WORD_PHASE_BITS: u32 = 27;
const WORD_PHASE_MASK: u64 = (1u64 << WORD_PHASE_BITS) - 1;
const INLINE_LEAF_MASKS: usize = 128;
const INLINE_PUT_RECORDS: usize = 128;
const MAX_BYPASS_LEAF_BLOCKS: usize = 32;

// Derive the packed block width from the production atomic representation.
// Loom atomics deliberately have a different size, so Loom models retain the
// production logical width while using Loom storage for each modeled word.
const CACHE_PADDING_BYTES: usize = size_of::<CachePadded<std::sync::atomic::AtomicU64>>();
const LEAF_WORDS_PER_BLOCK: usize = CACHE_PADDING_BYTES / size_of::<std::sync::atomic::AtomicU64>();

type LeafBlock = CachePadded<[AtomicU64; LEAF_WORDS_PER_BLOCK]>;

const _: () = assert!(LEAF_WORDS_PER_BLOCK.is_power_of_two());

#[cfg(not(feature = "loom"))]
const _: () = {
    assert!(size_of::<LeafBlock>() == CACHE_PADDING_BYTES);
    assert!(std::mem::align_of::<LeafBlock>() == std::mem::align_of::<CachePadded<AtomicU64>>());
};

#[derive(Clone, Copy)]
struct Geometry {
    capacity: usize,
    stripe_count: usize,
    stripe_mask: usize,
    stripe_shift: u32,
    max_logical_words: usize,
    base_chunk_words: usize,
    base_chunk_shift: u32,
    total_leaf_blocks: usize,
}

impl Geometry {
    fn new(capacity: usize, parallelism: usize) -> Self {
        let parallelism_stripes = parallelism
            .checked_next_power_of_two()
            .unwrap_or(MAX_FREELIST_STRIPES)
            .min(MAX_FREELIST_STRIPES);
        let capacity_target = capacity.div_ceil(TARGET_MAX_SLOTS_PER_STRIPE);
        let capacity_stripes = capacity_target
            .checked_next_power_of_two()
            .unwrap_or(MAX_FREELIST_STRIPES)
            .min(MAX_FREELIST_STRIPES);
        let capacity_ceiling = 1usize << capacity.ilog2();
        let stripe_count = parallelism_stripes
            .max(capacity_stripes)
            .min(capacity_ceiling);
        let stripe_shift = stripe_count.trailing_zeros();
        let stripe_mask = stripe_count - 1;
        let max_stripe_capacity = Self::stripe_capacity_for(capacity, stripe_shift, 0);
        let max_logical_words = max_stripe_capacity.div_ceil(SLOT_WORD_BITS);
        let base_chunk_words = max_logical_words
            .div_ceil(64)
            .checked_next_power_of_two()
            .expect("base chunk width must be representable");
        let base_chunk_shift = base_chunk_words.trailing_zeros();
        let mut total_leaf_blocks = 0usize;

        for stripe in 0..stripe_count {
            let stripe_capacity = Self::stripe_capacity_for(capacity, stripe_shift, stripe);
            let logical_words = stripe_capacity.div_ceil(SLOT_WORD_BITS);
            total_leaf_blocks = total_leaf_blocks
                .checked_add(logical_words.div_ceil(LEAF_WORDS_PER_BLOCK))
                .expect("leaf block count must be representable");
        }

        let geometry = Self {
            capacity,
            stripe_count,
            stripe_mask,
            stripe_shift,
            max_logical_words,
            base_chunk_words,
            base_chunk_shift,
            total_leaf_blocks,
        };
        geometry.validate();
        geometry
    }

    #[inline(always)]
    const fn stripe_capacity_for(capacity: usize, stripe_shift: u32, stripe: usize) -> usize {
        ((capacity - 1 - stripe) >> stripe_shift) + 1
    }

    #[inline(always)]
    const fn stripe_capacity(&self, stripe: usize) -> usize {
        Self::stripe_capacity_for(self.capacity, self.stripe_shift, stripe)
    }

    #[inline(always)]
    const fn slot(&self, stripe: usize, local: usize) -> usize {
        (local << self.stripe_shift) | stripe
    }

    fn validate(&self) {
        assert!(self.stripe_count.is_power_of_two());
        assert!(self.stripe_count <= self.capacity.min(MAX_FREELIST_STRIPES));
        assert!(self.max_logical_words <= 1 << 18);
        assert!(self.base_chunk_words <= 1 << 12);
        assert!(self.total_leaf_blocks > 0);

        let mut total_capacity = 0usize;
        for stripe in 0..self.stripe_count {
            let stripe_capacity = self.stripe_capacity(stripe);
            assert!(stripe_capacity <= TARGET_MAX_SLOTS_PER_STRIPE);
            total_capacity = total_capacity
                .checked_add(stripe_capacity)
                .expect("stripe capacities must be representable");
            let last = self.slot(stripe, stripe_capacity - 1);
            assert!(last < self.capacity);
            assert!(u32::try_from(last).is_ok());
        }
        assert_eq!(total_capacity, self.capacity);
    }
}

struct Stripe {
    summary: AtomicU64,
    leaves: Box<[LeafBlock]>,
    slots: Box<[CachePadded<UnsafeCell<PooledOwner>>]>,
    capacity: usize,
    logical_words: usize,
    valid_group_mask: u64,
    group_count: u32,
    single_groups: u32,
}

impl Stripe {
    #[inline(always)]
    fn leaf(&self, logical_word: usize) -> &AtomicU64 {
        let block = logical_word / LEAF_WORDS_PER_BLOCK;
        let offset = logical_word & (LEAF_WORDS_PER_BLOCK - 1);
        &self.leaves[block][offset]
    }

    #[inline(always)]
    fn valid_leaf_mask(&self, logical_word: usize) -> u64 {
        let remaining = self.capacity - logical_word * SLOT_WORD_BITS;
        low_bits(remaining.min(SLOT_WORD_BITS))
    }
}

#[cfg(not(feature = "loom"))]
const _: () = assert!(size_of::<CachePadded<Stripe>>() == CACHE_PADDING_BYTES);

struct CreationCursor {
    state: AtomicU64,
}

impl CreationCursor {
    #[inline(always)]
    #[allow(clippy::missing_const_for_fn)]
    fn new(state: u64) -> Self {
        Self {
            state: AtomicU64::new(state),
        }
    }

    #[inline(always)]
    fn claim(&self, probe_phase: u64, capacity: usize) -> Option<(u64, usize)> {
        #[allow(deprecated)]
        let previous = self
            .state
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
                if state == 0 {
                    Some(encode_cursor(probe_phase, 1))
                } else {
                    let next = decode_cursor_next(state);
                    if next < capacity {
                        Some(encode_cursor(decode_cursor_phase(state), next + 1))
                    } else {
                        None
                    }
                }
            })
            .ok()?;

        if previous == 0 {
            Some((probe_phase, 0))
        } else {
            Some((decode_cursor_phase(previous), decode_cursor_next(previous)))
        }
    }
}

#[derive(Clone, Copy)]
struct PutRecord<'a> {
    stripe: usize,
    word: usize,
    mask: u64,
    group_mask: u64,
    leaf: &'a AtomicU64,
    summary: &'a AtomicU64,
}

// The inline variant is intentionally stack-resident. Boxing it would add an
// allocation to ordinary large-geometry spill batches.
#[allow(clippy::large_enum_variant)]
enum PutRecords<'a> {
    Inline {
        records: [MaybeUninit<PutRecord<'a>>; INLINE_PUT_RECORDS],
        len: usize,
    },
    Heap(Vec<PutRecord<'a>>),
}

impl<'a> PutRecords<'a> {
    #[inline(always)]
    const fn new() -> Self {
        Self::Inline {
            records: [MaybeUninit::uninit(); INLINE_PUT_RECORDS],
            len: 0,
        }
    }

    #[inline(always)]
    fn with_capacity(capacity: usize) -> Self {
        if capacity <= INLINE_PUT_RECORDS {
            Self::new()
        } else {
            Self::Heap(Vec::with_capacity(capacity))
        }
    }

    #[inline(always)]
    fn push(&mut self, record: PutRecord<'a>) {
        match self {
            Self::Inline { records, len } if *len < INLINE_PUT_RECORDS => {
                records[*len].write(record);
                *len += 1;
            }
            Self::Inline { records, len } => {
                let mut heap = Vec::with_capacity(*len + 1);
                for record in &records[..*len] {
                    // SAFETY: every record before `len` was initialized by
                    // `push`, and `PutRecord` has no drop glue.
                    heap.push(unsafe { record.assume_init_read() });
                }
                heap.push(record);
                *self = Self::Heap(heap);
            }
            Self::Heap(records) => records.push(record),
        }
    }

    #[inline(always)]
    const fn as_mut_slice(&mut self) -> &mut [PutRecord<'a>] {
        match self {
            Self::Inline { records, len } => {
                // SAFETY: the initialized prefix contains `len` contiguous
                // `PutRecord` values and the returned slice does not expose
                // the uninitialized tail.
                unsafe { slice::from_raw_parts_mut(records.as_mut_ptr().cast(), *len) }
            }
            Self::Heap(records) => records.as_mut_slice(),
        }
    }
}

#[inline(always)]
const fn low_bits(bits: usize) -> u64 {
    assert!(bits > 0 && bits <= SLOT_WORD_BITS);
    if bits == SLOT_WORD_BITS {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

#[inline(always)]
const fn group_mask(group: usize) -> u64 {
    1u64 << group
}

#[inline(always)]
const fn encode_code(group: usize) -> u64 {
    ((group as u64) + 1) << CODE_SHIFT
}

#[inline(always)]
const fn raw_code(state: u64) -> usize {
    ((state & CODE_MASK) >> CODE_SHIFT) as usize
}

#[inline(always)]
const fn decode_code(state: u64) -> Option<usize> {
    let raw = raw_code(state);
    assert!(raw <= AVAILABILITY_BITS);
    if raw == 0 { None } else { Some(raw - 1) }
}

#[inline(always)]
const fn encode_cursor(probe_phase: u64, next: usize) -> u64 {
    (probe_phase << CURSOR_NEXT_BITS) | next as u64
}

#[inline(always)]
const fn decode_cursor_next(state: u64) -> usize {
    (state & CURSOR_NEXT_MASK) as usize
}

#[inline(always)]
const fn decode_cursor_phase(state: u64) -> u64 {
    (state >> CURSOR_NEXT_BITS) & PROBE_PHASE_MASK
}

#[inline(always)]
const fn reduce_word_phase(word_phase: u32, words: usize) -> usize {
    (((word_phase as u64) * (words as u64)) >> WORD_PHASE_BITS) as usize
}

#[inline(always)]
const fn next_admission(created: usize, capacity: usize) -> Option<usize> {
    if created < capacity {
        Some(created + 1)
    } else {
        None
    }
}

#[inline(always)]
const fn mix_probe_id(id: u64) -> u64 {
    let mut mixed = id;
    mixed ^= mixed >> 30;
    mixed = mixed.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed ^= mixed >> 27;
    mixed = mixed.wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

fn assert_allocation<T>(len: usize) {
    Layout::array::<T>(len).expect("freelist allocation must be representable");
}

fn group_geometry(
    logical_words: usize,
    base_chunk_words: usize,
    max_groups: usize,
) -> (u32, u32, u64) {
    assert!(max_groups > 0 && max_groups <= AVAILABILITY_BITS);
    let base_chunks = logical_words.div_ceil(base_chunk_words);
    assert!(base_chunks <= max_groups * 2);
    let paired = base_chunks.saturating_sub(max_groups);
    let single = base_chunks - paired * 2;
    let groups = single + paired;
    assert!(groups > 0 && groups <= max_groups);
    (groups as u32, single as u32, low_bits(groups))
}

#[inline(always)]
const fn group_for_base(single_groups: usize, base: usize) -> usize {
    if base < single_groups {
        base
    } else {
        single_groups + ((base - single_groups) >> 1)
    }
}

#[inline(always)]
const fn group_base_range(single_groups: usize, group: usize) -> (usize, usize) {
    if group < single_groups {
        (group, 1)
    } else {
        (single_groups + (group - single_groups) * 2, 2)
    }
}

#[derive(Clone, Copy)]
struct ConstructionOptions {
    force_summaries: bool,
    max_groups: usize,
}

impl Default for ConstructionOptions {
    fn default() -> Self {
        Self {
            force_summaries: false,
            max_groups: AVAILABILITY_BITS,
        }
    }
}

struct CleanupGuard<'a> {
    summary: &'a AtomicU64,
    group_mask: u64,
    armed: bool,
}

impl<'a> CleanupGuard<'a> {
    #[inline(always)]
    const fn new(summary: &'a AtomicU64, group_mask: u64) -> Self {
        Self {
            summary,
            group_mask,
            armed: true,
        }
    }

    #[inline(always)]
    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CleanupGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.summary.fetch_or(self.group_mask, Ordering::Release);
        self.summary.fetch_and(AVAILABILITY_MASK, Ordering::Release);
    }
}

struct TakeContext<'a, F> {
    max: usize,
    filled: usize,
    on_entry: &'a mut F,
}

impl<F> TakeContext<'_, F> {
    #[inline(always)]
    const fn is_full(&self) -> bool {
        self.filled == self.max
    }
}

/// Bounded lock-free freelist of tracked buffers for one size class.
pub struct Freelist {
    layout: Layout,
    capacity: usize,
    created: CachePadded<AtomicUsize>,
    stripes: Box<[CachePadded<Stripe>]>,
    creation_cursors: Box<[CachePadded<CreationCursor>]>,
    stripe_mask: usize,
    stripe_shift: u32,
    base_chunk_words: usize,
    base_chunk_shift: u32,
    summaries_enabled: bool,
}

// SAFETY: each owner entry is mutated only while its authoritative leaf bit is
// clear and the slot is exclusively owned. Release publication and Acquire
// claims synchronize ownership transfers.
unsafe impl Send for Freelist {}
// SAFETY: the same slot ownership and leaf synchronization apply to shared
// access. Stripe-local owner pointees remain stable until the freelist drops.
unsafe impl Sync for Freelist {}

impl Freelist {
    /// Creates a new fixed-capacity freelist.
    ///
    /// `parallelism` is the expected number of threads contending for the
    /// freelist. Capacity may raise the internal stripe count to keep each
    /// search domain bounded.
    ///
    /// If `prefill` is true, creates `capacity` buffers and makes them
    /// immediately available in the freelist.
    pub fn new(
        capacity: NonZeroU32,
        parallelism: NonZeroUsize,
        layout: Layout,
        prefill: bool,
    ) -> Self {
        Self::new_inner(
            capacity,
            parallelism,
            layout,
            prefill,
            ConstructionOptions::default(),
        )
    }

    fn new_inner(
        capacity: NonZeroU32,
        parallelism: NonZeroUsize,
        layout: Layout,
        prefill: bool,
        options: ConstructionOptions,
    ) -> Self {
        assert!(layout.size() > 0, "layout size must be non-zero");
        let capacity = capacity.get() as usize;
        let geometry = Geometry::new(capacity, parallelism.get());
        let summaries_enabled = options.force_summaries
            || !cfg!(target_arch = "x86_64")
            || geometry.total_leaf_blocks > MAX_BYPASS_LEAF_BLOCKS;

        assert_allocation::<CachePadded<Stripe>>(geometry.stripe_count);
        assert_allocation::<CachePadded<CreationCursor>>(geometry.stripe_count);

        let mut stripes = Vec::with_capacity(geometry.stripe_count);
        let mut creation_cursors = Vec::with_capacity(geometry.stripe_count);

        for stripe_index in 0..geometry.stripe_count {
            let stripe_capacity = geometry.stripe_capacity(stripe_index);
            let logical_words = stripe_capacity.div_ceil(SLOT_WORD_BITS);
            let leaf_blocks = logical_words.div_ceil(LEAF_WORDS_PER_BLOCK);
            let (group_count, single_groups, valid_group_mask) =
                group_geometry(logical_words, geometry.base_chunk_words, options.max_groups);

            assert_allocation::<LeafBlock>(leaf_blocks);
            assert_allocation::<CachePadded<UnsafeCell<PooledOwner>>>(stripe_capacity);

            let leaves = (0..leaf_blocks)
                .map(|block| {
                    let words = std::array::from_fn(|offset| {
                        let logical_word = block * LEAF_WORDS_PER_BLOCK + offset;
                        let bits = if prefill && logical_word < logical_words {
                            let remaining = stripe_capacity - logical_word * SLOT_WORD_BITS;
                            low_bits(remaining.min(SLOT_WORD_BITS))
                        } else {
                            0
                        };
                        AtomicU64::new(bits)
                    });
                    CachePadded::new(words)
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let slots = (0..stripe_capacity)
                .map(|local| {
                    let slot = geometry.slot(stripe_index, local);
                    let slot = u32::try_from(slot).expect("slot id must fit in u32");
                    CachePadded::new(UnsafeCell::new(PooledOwner::new(slot, layout.size())))
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let summary = if prefill && summaries_enabled {
                valid_group_mask
            } else {
                0
            };
            let cursor = if prefill {
                encode_cursor(0, stripe_capacity)
            } else {
                0
            };

            stripes.push(CachePadded::new(Stripe {
                summary: AtomicU64::new(summary),
                leaves,
                slots,
                capacity: stripe_capacity,
                logical_words,
                valid_group_mask,
                group_count,
                single_groups,
            }));
            creation_cursors.push(CachePadded::new(CreationCursor::new(cursor)));
        }

        let freelist = Self {
            layout,
            capacity,
            created: CachePadded::new(AtomicUsize::new(if prefill { capacity } else { 0 })),
            stripes: stripes.into_boxed_slice(),
            creation_cursors: creation_cursors.into_boxed_slice(),
            stripe_mask: geometry.stripe_mask,
            stripe_shift: geometry.stripe_shift,
            base_chunk_words: geometry.base_chunk_words,
            base_chunk_shift: geometry.base_chunk_shift,
            summaries_enabled,
        };

        if prefill {
            for (stripe_index, stripe) in freelist.stripes.iter().enumerate() {
                for local in 0..stripe.capacity {
                    // SAFETY: construction exclusively owns every eagerly
                    // initialized owner entry. Leaf bits are not shared until
                    // construction returns.
                    let _ = unsafe {
                        PooledBuffer::new(freelist.owner_ptr(stripe_index, local), layout, false)
                    };
                }
            }
        }

        freelist
    }

    #[cfg(test)]
    pub(super) fn new_forced_summary(
        capacity: NonZeroU32,
        parallelism: NonZeroUsize,
        layout: Layout,
        prefill: bool,
    ) -> Self {
        Self::new_inner(
            capacity,
            parallelism,
            layout,
            prefill,
            ConstructionOptions {
                force_summaries: true,
                max_groups: AVAILABILITY_BITS,
            },
        )
    }

    /// Creates a new buffer and reserves a stable slot id for it.
    ///
    /// Creation has two steps. First, `created` claims one capacity permit.
    /// Then a stripe-local cursor assigns the actual slot id using the same
    /// per-thread probe phases as [`Self::take`]. This keeps newly-created
    /// buffers mapped to the groups and words their creating thread will probe
    /// first after those buffers are returned to the global freelist.
    ///
    /// Returns `None` once every creation permit in the fixed-capacity
    /// freelist has been claimed.
    ///
    /// The returned buffer does not deallocate itself. It must be returned to
    /// this same freelist before the freelist is finally dropped, otherwise
    /// its allocation leaks and its owner pointer dangles.
    #[inline(always)]
    pub(super) fn try_create(&self, zeroed: bool) -> Option<PooledBuffer> {
        let probe = Probe::new(self.stripe_mask);

        // `created` admits exactly `capacity` creators. It does not publish a
        // buffer or a slot id, so relaxed ordering is enough.
        //
        // Loom's atomic implementation does not provide `try_update`.
        #[allow(deprecated)]
        self.created
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |created| {
                next_admission(created, self.capacity)
            })
            .ok()?;

        for scanned in 0..self.stripes.len() {
            let stripe_index = probe.stripe(scanned, self.stripe_mask);
            let stripe = &self.stripes[stripe_index];
            let cursor = &self.creation_cursors[stripe_index];
            let Some((probe_phase, ticket)) = cursor.claim(probe.phase(), stripe.capacity) else {
                continue;
            };
            let cursor_probe = Probe::from_phase(stripe_index, probe_phase);
            let local = self.unrank_local(stripe, cursor_probe, ticket);

            // SAFETY: the cursor assigned this local owner exactly once. All
            // preparation that can fail happened before admission.
            let buffer = unsafe {
                PooledBuffer::new(self.owner_ptr(stripe_index, local), self.layout, zeroed)
            };
            return Some(buffer);
        }

        unreachable!("creation permit guarantees one cursor with capacity")
    }

    #[inline(always)]
    const fn slot_location(&self, slot: u32) -> (usize, usize, usize, u64) {
        let slot = slot as usize;
        let stripe = slot & self.stripe_mask;
        let local = slot >> self.stripe_shift;
        let word = local >> SLOT_WORD_SHIFT;
        let mask = 1u64 << (local & (SLOT_WORD_BITS - 1));
        (stripe, local, word, mask)
    }

    #[inline(always)]
    #[cfg(all(test, not(feature = "loom")))]
    const fn slot_index(&self, stripe: usize, local: usize) -> u32 {
        ((local << self.stripe_shift) | stripe) as u32
    }

    #[inline(always)]
    const fn group_for_word(&self, stripe: &Stripe, word: usize) -> usize {
        let base = word >> self.base_chunk_shift;
        group_for_base(stripe.single_groups as usize, base)
    }

    #[inline(always)]
    fn group_word_range(&self, stripe: &Stripe, group: usize) -> (usize, usize, usize) {
        let (base, base_count) = group_base_range(stripe.single_groups as usize, group);
        let start = base << self.base_chunk_shift;
        let full_words = base_count * self.base_chunk_words;
        let end = start.saturating_add(full_words).min(stripe.logical_words);
        (start, end, full_words)
    }

    #[inline(always)]
    fn group_slot_count(&self, stripe: &Stripe, group: usize) -> usize {
        let (start, end, _) = self.group_word_range(stripe, group);
        (end * SLOT_WORD_BITS).min(stripe.capacity) - start * SLOT_WORD_BITS
    }

    #[inline(always)]
    const fn word_offset(probe: Probe, words: usize, full_words: Option<usize>) -> usize {
        if let Some(full_words) = full_words
            && words == full_words
        {
            return probe.word_phase as usize & (full_words - 1);
        }
        reduce_word_phase(probe.word_phase, words)
    }

    fn unrank_local(&self, stripe: &Stripe, probe: Probe, mut ticket: usize) -> usize {
        if !self.summaries_enabled {
            return self.unrank_span(stripe, probe, 0, stripe.logical_words, None, ticket);
        }

        let group_count = stripe.group_count as usize;
        for offset in 0..group_count {
            let group = probe.group(offset, group_count);
            let slots = self.group_slot_count(stripe, group);
            if ticket < slots {
                let (start, end, full_words) = self.group_word_range(stripe, group);
                return self.unrank_span(stripe, probe, start, end, Some(full_words), ticket);
            }
            ticket -= slots;
        }

        unreachable!("cursor ticket must map to one local slot")
    }

    fn unrank_span(
        &self,
        stripe: &Stripe,
        probe: Probe,
        start: usize,
        end: usize,
        full_words: Option<usize>,
        ticket: usize,
    ) -> usize {
        let words = end - start;
        let offset = Self::word_offset(probe, words, full_words);
        let split = start + offset;
        let ticket = match self.unrank_run(stripe, probe, split, end, ticket) {
            Ok(local) => return local,
            Err(ticket) => ticket,
        };
        self.unrank_run(stripe, probe, start, split, ticket)
            .unwrap_or_else(|_| unreachable!("span ticket must map to one local slot"))
    }

    const fn unrank_run(
        &self,
        stripe: &Stripe,
        probe: Probe,
        start: usize,
        end: usize,
        mut ticket: usize,
    ) -> Result<usize, usize> {
        if start == end {
            return Err(ticket);
        }

        let partial_bits = stripe.capacity & (SLOT_WORD_BITS - 1);
        let has_partial = partial_bits != 0 && end == stripe.logical_words;
        let full_end = if has_partial { end - 1 } else { end };
        let full_slots = (full_end - start) * SLOT_WORD_BITS;
        if ticket < full_slots {
            let word = start + ticket / SLOT_WORD_BITS;
            let rank = ticket & (SLOT_WORD_BITS - 1);
            let bit = (rank + probe.bit_phase as usize) & (SLOT_WORD_BITS - 1);
            return Ok(word * SLOT_WORD_BITS + bit);
        }
        ticket -= full_slots;

        if has_partial {
            let valid = low_bits(partial_bits);
            if ticket < partial_bits {
                let bit = probe.select_ranked_bit(valid, ticket);
                return Ok((end - 1) * SLOT_WORD_BITS + bit);
            }
            ticket -= partial_bits;
        }

        Err(ticket)
    }

    /// Puts one tracked buffer into the global freelist.
    ///
    /// The buffer's slot id is read from its side-table entry, then that slot's
    /// free bit is set with `Release` ordering. A successful `take` performs
    /// the matching `Acquire` operation before rebuilding a buffer handle from
    /// the same side-table entry.
    ///
    /// The caller must own `buffer`, its slot must not already be available in
    /// this freelist, and the buffer must have been created by this freelist.
    ///
    /// # Panics
    ///
    /// Panics if the slot is already free in this freelist.
    #[inline]
    pub fn put(&self, buffer: PooledBuffer) {
        let slot = buffer.slot();
        let (stripe_index, _, word, mask) = self.slot_location(slot);
        let stripe = &self.stripes[stripe_index];
        let leaf = stripe.leaf(word);
        let summary = &stripe.summary;
        let group = group_mask(self.group_for_word(stripe, word));

        let previous = leaf.fetch_or(mask, Ordering::Release);
        if self.summaries_enabled {
            // Every completed summarized return publishes unconditionally.
            // The RMW preserves both sibling availability and any active code.
            summary.fetch_or(group, Ordering::Release);
        }
        assert_eq!(
            previous & mask,
            0,
            "returned slot must not already be marked free"
        );
    }

    /// Puts several tracked buffers into the global freelist.
    ///
    /// Batch insertion groups returned slots by leaf word, so each touched word
    /// needs one atomic `fetch_or` regardless of how many entries map to it.
    /// Summarized stripes then publish all touched groups with one additional
    /// atomic `fetch_or` per stripe.
    ///
    /// `BufferPool` callers pass simple non-panicking iterators over entries
    /// they already own. Avoiding per-entry guards keeps this path
    /// allocation-free for ordinary batches.
    ///
    /// The caller must own every buffer in the batch. Slots must be unique
    /// within the batch (staging asserts this) and must not already be
    /// available in this freelist (asserted per word on insert). Each buffer
    /// must have been created by this freelist. If this method panics after
    /// accepting one or more buffers, accepted-but-unpublished buffers may
    /// leak.
    #[inline]
    pub fn put_batch(&self, entries: impl IntoIterator<Item = PooledBuffer>) {
        let mut entries = entries.into_iter();
        let Some(buffer) = entries.next() else {
            return;
        };
        let Some(next_buffer) = entries.next() else {
            self.put(buffer);
            return;
        };

        let dense_len = self.stripes.len() * self.stripes[0].logical_words;
        if dense_len <= INLINE_LEAF_MASKS {
            let mut masks = MaybeUninit::<[u64; INLINE_LEAF_MASKS]>::uninit();
            // SAFETY: only the active dense prefix is initialized and exposed.
            let masks = unsafe {
                let ptr = masks.as_mut_ptr().cast::<u64>();
                ptr.write_bytes(0, dense_len);
                slice::from_raw_parts_mut(ptr, dense_len)
            };
            let stride = self.stripes[0].logical_words;
            self.stage_dense(masks, stride, buffer);
            self.stage_dense(masks, stride, next_buffer);
            for buffer in entries {
                self.stage_dense(masks, stride, buffer);
            }

            let mut records = PutRecords::new();
            for (index, &mask) in masks.iter().enumerate() {
                if mask == 0 {
                    continue;
                }
                let stripe = index / stride;
                let word = index % stride;
                records.push(self.put_record(stripe, word, mask));
            }
            self.publish_records(records.as_mut_slice());
        } else {
            let (lower, upper) = entries.size_hint();
            let remaining = upper.filter(|upper| *upper == lower).unwrap_or(lower);
            let capacity = remaining
                .checked_add(2)
                .expect("put batch length exceeds address space");
            let mut records = PutRecords::with_capacity(capacity);
            self.stage_record(&mut records, buffer);
            self.stage_record(&mut records, next_buffer);
            for buffer in entries {
                self.stage_record(&mut records, buffer);
            }

            let records = records.as_mut_slice();
            records.sort_unstable_by_key(|record| (record.stripe, record.word, record.mask));
            let len = Self::coalesce_records(records);
            self.publish_records(&records[..len]);
        }
    }

    #[inline(always)]
    fn stage_dense(&self, masks: &mut [u64], stride: usize, buffer: PooledBuffer) {
        let (stripe, _, word, mask) = self.slot_location(buffer.slot());
        let index = stripe * stride + word;
        assert_eq!(masks[index] & mask, 0, "duplicate slot in put_batch");
        masks[index] |= mask;
    }

    #[inline(always)]
    fn stage_record<'a>(&'a self, records: &mut PutRecords<'a>, buffer: PooledBuffer) {
        let (stripe, _, word, mask) = self.slot_location(buffer.slot());
        records.push(self.put_record(stripe, word, mask));
    }

    #[inline(always)]
    fn put_record(&self, stripe_index: usize, word: usize, mask: u64) -> PutRecord<'_> {
        let stripe = &self.stripes[stripe_index];
        PutRecord {
            stripe: stripe_index,
            word,
            mask,
            group_mask: group_mask(self.group_for_word(stripe, word)),
            leaf: stripe.leaf(word),
            summary: &stripe.summary,
        }
    }

    #[inline(always)]
    fn coalesce_records(records: &mut [PutRecord<'_>]) -> usize {
        let mut len = 0;
        for read in 0..records.len() {
            let record = records[read];
            if len > 0
                && records[len - 1].stripe == record.stripe
                && records[len - 1].word == record.word
            {
                assert_eq!(
                    records[len - 1].mask & record.mask,
                    0,
                    "duplicate slot in put_batch"
                );
                records[len - 1].mask |= record.mask;
                records[len - 1].group_mask |= record.group_mask;
            } else {
                records[len] = record;
                len += 1;
            }
        }
        len
    }

    fn publish_records(&self, records: &[PutRecord<'_>]) {
        let Some(first) = records.first() else {
            return;
        };
        let mut stripe = first.stripe;
        let mut summary = first.summary;
        let mut groups = 0u64;
        let mut overlap = 0u64;

        for record in records {
            if record.stripe != stripe {
                if self.summaries_enabled {
                    summary.fetch_or(groups, Ordering::Release);
                }
                assert_eq!(
                    overlap, 0,
                    "returned slot batch must not already contain a free slot"
                );
                stripe = record.stripe;
                summary = record.summary;
                groups = 0;
                overlap = 0;
            }

            overlap |= record.leaf.fetch_or(record.mask, Ordering::Release) & record.mask;
            groups |= record.group_mask;
        }

        if self.summaries_enabled {
            summary.fetch_or(groups, Ordering::Release);
        }
        assert_eq!(
            overlap, 0,
            "returned slot batch must not already contain a free slot"
        );
    }

    /// Takes any one available slot from the global freelist.
    ///
    /// On success, ownership of the returned buffer is transferred to the
    /// caller. The buffer must be returned to this same freelist before the
    /// freelist is finally dropped, otherwise it leaks.
    ///
    /// The search starts from a stable per-thread home word and scans the other
    /// stripes only on miss. Within a word, `fetch_and` claims one bit. That is
    /// important: unlike a full-word CAS loop, two threads removing different
    /// bits from the same word can both succeed.
    #[inline]
    pub fn take(&self) -> Option<PooledBuffer> {
        let mut result = None;
        self.take_with_probe(Probe::new(self.stripe_mask), 1, &mut |buffer| {
            result = Some(buffer);
        });
        result
    }

    /// Takes up to `max` available slots from the global freelist.
    ///
    /// Ownership of each claimed buffer is transferred to `on_entry`. Each
    /// buffer must be returned to this same freelist before the freelist is
    /// finally dropped, otherwise it leaks.
    ///
    /// `on_entry` receives each claimed buffer. This avoids internal
    /// allocation and lets callers fill an existing spill/refill buffer
    /// directly. `on_entry` **must not panic**: for batch claims, bits are
    /// cleared before buffers are handed to the callback, so a panic could
    /// strand already-claimed slots outside the freelist.
    ///
    /// For `max > 1`, the implementation tries to claim several bits from the
    /// same word in a single atomic `fetch_and`, which amortizes the shared
    /// synchronization cost across the batch.
    #[inline]
    pub fn take_batch(&self, max: usize, mut on_entry: impl FnMut(PooledBuffer)) -> usize {
        if max == 0 {
            return 0;
        }
        self.take_with_probe(Probe::new(self.stripe_mask), max, &mut on_entry)
    }

    fn take_with_probe(
        &self,
        probe: Probe,
        max: usize,
        on_entry: &mut impl FnMut(PooledBuffer),
    ) -> usize {
        let mut context = TakeContext {
            max,
            filled: 0,
            on_entry,
        };
        for scanned in 0..self.stripes.len() {
            let stripe_index = probe.stripe(scanned, self.stripe_mask);
            let stripe = &self.stripes[stripe_index];
            if self.summaries_enabled {
                self.scan_summarized_stripe(stripe_index, stripe, probe, &mut context);
            } else {
                self.scan_bypass_stripe(stripe_index, stripe, probe, &mut context);
            }
            if context.is_full() {
                break;
            }
        }
        context.filled
    }

    fn scan_bypass_stripe(
        &self,
        stripe_index: usize,
        stripe: &Stripe,
        probe: Probe,
        context: &mut TakeContext<'_, impl FnMut(PooledBuffer)>,
    ) {
        let mut word = reduce_word_phase(probe.word_phase, stripe.logical_words);
        for _ in 0..stripe.logical_words {
            let candidates = stripe.leaf(word).load(Ordering::Acquire);
            self.claim_word(stripe_index, stripe, word, candidates, probe, context);
            if context.is_full() {
                return;
            }
            word += 1;
            if word == stripe.logical_words {
                word = 0;
            }
        }
    }

    fn scan_summarized_stripe(
        &self,
        stripe_index: usize,
        stripe: &Stripe,
        probe: Probe,
        context: &mut TakeContext<'_, impl FnMut(PooledBuffer)>,
    ) {
        let state = stripe.summary.load(Ordering::Acquire);
        if state == 0 {
            return;
        }

        let mut low_pending = state & stripe.valid_group_mask;
        let mut code_pending = 0u64;
        let mut processed = 0u64;
        if let Some(group) = decode_code(state) {
            Self::add_code_candidate(stripe, group, processed, &mut code_pending);
        }

        while low_pending != 0 {
            let group = probe.select_group(low_pending, stripe.group_count as usize);
            let mask = group_mask(group);
            low_pending &= !mask;
            processed |= mask;
            let repair = code_pending & mask != 0;
            code_pending &= !mask;

            let before = context.filled;
            self.scan_group(stripe_index, stripe, group, probe, repair, context);
            if context.is_full() {
                return;
            }
            if context.filled != before {
                continue;
            }

            let current = stripe.summary.load(Ordering::Acquire);
            if let Some(code_group) = decode_code(current) {
                Self::add_code_candidate(stripe, code_group, processed, &mut code_pending);
                continue;
            }
            if current & mask == 0 {
                continue;
            }

            let desired = (current & AVAILABILITY_MASK & !mask) | encode_code(group);
            match stripe.summary.compare_exchange(
                current,
                desired,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => self.clean_owned_group(stripe_index, stripe, group, probe, context),
                Err(actual) => {
                    if let Some(code_group) = decode_code(actual) {
                        Self::add_code_candidate(stripe, code_group, processed, &mut code_pending);
                    }
                }
            }
            if context.is_full() {
                return;
            }
        }

        while code_pending != 0 {
            let group = probe.select_group(code_pending, stripe.group_count as usize);
            let mask = group_mask(group);
            code_pending &= !mask;
            if processed & mask != 0 {
                continue;
            }
            processed |= mask;
            self.scan_group(stripe_index, stripe, group, probe, true, context);
            if context.is_full() {
                return;
            }
        }
    }

    #[inline(always)]
    fn add_code_candidate(stripe: &Stripe, group: usize, processed: u64, pending: &mut u64) {
        assert!(group < stripe.group_count as usize);
        *pending |= group_mask(group) & !processed;
    }

    fn scan_group(
        &self,
        stripe_index: usize,
        stripe: &Stripe,
        group: usize,
        probe: Probe,
        repair: bool,
        context: &mut TakeContext<'_, impl FnMut(PooledBuffer)>,
    ) {
        let (start, end, full_words) = self.group_word_range(stripe, group);
        let words = end - start;
        let offset = Self::word_offset(probe, words, Some(full_words));
        let mut word = start + offset;
        let mask = group_mask(group);

        for _ in 0..words {
            let candidates = stripe.leaf(word).load(Ordering::Acquire);
            if repair && candidates != 0 {
                stripe.summary.fetch_or(mask, Ordering::Release);
            }
            self.claim_word(stripe_index, stripe, word, candidates, probe, context);
            if context.is_full() {
                return;
            }
            word += 1;
            if word == end {
                word = start;
            }
        }
    }

    fn clean_owned_group(
        &self,
        stripe_index: usize,
        stripe: &Stripe,
        group: usize,
        probe: Probe,
        context: &mut TakeContext<'_, impl FnMut(PooledBuffer)>,
    ) {
        let mask = group_mask(group);
        let mut guard = CleanupGuard::new(&stripe.summary, mask);
        let (start, end, full_words) = self.group_word_range(stripe, group);
        let words = end - start;
        let offset = Self::word_offset(probe, words, Some(full_words));
        let mut word = start + offset;

        for visited in 0..words {
            let candidates = stripe.leaf(word).load(Ordering::Acquire);
            if candidates != 0 {
                stripe.summary.fetch_or(mask, Ordering::Release);
                guard.disarm();
                stripe
                    .summary
                    .fetch_and(AVAILABILITY_MASK, Ordering::Release);
                self.claim_word(stripe_index, stripe, word, candidates, probe, context);
                if context.is_full() {
                    return;
                }

                word += 1;
                if word == end {
                    word = start;
                }
                for _ in visited + 1..words {
                    let candidates = stripe.leaf(word).load(Ordering::Acquire);
                    self.claim_word(stripe_index, stripe, word, candidates, probe, context);
                    if context.is_full() {
                        return;
                    }
                    word += 1;
                    if word == end {
                        word = start;
                    }
                }
                return;
            }

            word += 1;
            if word == end {
                word = start;
            }
        }

        guard.disarm();
        stripe
            .summary
            .fetch_and(AVAILABILITY_MASK, Ordering::Release);
    }

    fn claim_word(
        &self,
        stripe_index: usize,
        stripe: &Stripe,
        word: usize,
        mut candidates: u64,
        probe: Probe,
        context: &mut TakeContext<'_, impl FnMut(PooledBuffer)>,
    ) {
        let valid = stripe.valid_leaf_mask(word);
        candidates &= valid;
        let mut attempted = 0u64;

        while candidates != 0 && !context.is_full() {
            let claim = probe.select_set_bits(candidates, context.max - context.filled);
            attempted |= claim;
            let observed = stripe.leaf(word).fetch_and(!claim, Ordering::Acquire);
            let mut claimed = observed & claim;

            while claimed != 0 {
                let bit = probe.select_set_bit(claimed);
                let local = word * SLOT_WORD_BITS + bit;
                (context.on_entry)(self.buffer(stripe_index, local));
                claimed &= !(1u64 << bit);
                context.filled += 1;
            }

            candidates |= observed & valid & !attempted;
            candidates &= !attempted;
        }
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

        for (stripe_index, stripe) in self.stripes.iter().enumerate() {
            for word in 0..stripe.logical_words {
                let mut claimed = stripe.leaf(word).swap(0, Ordering::Acquire);

                while claimed != 0 {
                    let bit = claimed.trailing_zeros() as usize;
                    let local = word * SLOT_WORD_BITS + bit;
                    let buffer = self.buffer(stripe_index, local);
                    // SAFETY: this freelist allocated this slot with `layout`.
                    unsafe { buffer.deallocate(self.layout) };
                    claimed &= claimed - 1;
                    drained += 1;
                }
            }
        }

        drained
    }

    /// Returns the side-table pointer for a slot id.
    #[inline(always)]
    #[cfg(all(test, not(feature = "loom")))]
    fn slot_ptr(&self, slot: u32) -> ptr::NonNull<PooledOwner> {
        let (stripe, local, _, _) = self.slot_location(slot);
        self.owner_ptr(stripe, local)
    }

    #[inline(always)]
    fn owner_ptr(&self, stripe: usize, local: usize) -> ptr::NonNull<PooledOwner> {
        let cell = self.stripes[stripe]
            .slots
            .get(local)
            .expect("slot id must refer to an allocated slot");

        cfg_if::cfg_if! {
            if #[cfg(not(feature = "loom"))] {
                ptr::NonNull::new(cell.get()).expect("slot pointers are non-null")
            } else {
                cell.with(|ptr| {
                    ptr::NonNull::new(ptr.cast_mut()).expect("slot pointers are non-null")
                })
            }
        }
    }

    /// Rebuilds a pooled buffer handle for a claimed slot.
    ///
    /// The caller must have cleared the slot's free bit or freshly reserved
    /// the slot before calling this method.
    #[inline(always)]
    fn buffer(&self, stripe: usize, local: usize) -> PooledBuffer {
        // SAFETY: the caller owns the slot and its data allocation is live.
        let buffer = unsafe { PooledBuffer::from_owner(self.owner_ptr(stripe, local)) };
        // Under loom, every claim validates that the parked slot's refcount
        // sentinel was restored before the bitmap publication.
        #[cfg(feature = "loom")]
        buffer.assert_parked_sentinel();
        buffer
    }
}

impl Drop for Freelist {
    fn drop(&mut self) {
        // Any slot still free in the freelist owns a live pooled allocation.
        // Drain it explicitly before the side-table storage goes away.
        self.drain();
    }
}

#[derive(Clone, Copy)]
struct ProbeId {
    raw: usize,
    mixed: u64,
}

#[derive(Clone, Copy)]
struct Probe {
    home_stripe: usize,
    group_phase: u32,
    word_phase: u32,
    bit_phase: u32,
}

// Monotonic source for per-thread probe ids.
cfg_if::cfg_if! {
    if #[cfg(not(feature = "loom"))] {
        static NEXT_PROBE_ID: AtomicUsize = AtomicUsize::new(0);
    } else {
        loom::lazy_static! {
            static ref NEXT_PROBE_ID: AtomicUsize = AtomicUsize::new(0);
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(feature = "loom"))] {
        thread_local! {
            static TLS_PROBE_ID: Cell<Option<ProbeId>> = const { Cell::new(None) };
        }
    } else {
        loom::thread_local! {
            static TLS_PROBE_ID: Cell<Option<ProbeId>> = Cell::new(None);
        }
    }
}

impl Probe {
    #[inline(always)]
    fn new(stripe_mask: usize) -> Self {
        let id = TLS_PROBE_ID.with(|probe_id| {
            if let Some(id) = probe_id.get() {
                return id;
            }

            let raw = NEXT_PROBE_ID.fetch_add(1, Ordering::Relaxed);
            let id = ProbeId {
                raw,
                mixed: mix_probe_id(raw as u64),
            };
            probe_id.set(Some(id));
            id
        });
        Self::from_id(id, stripe_mask)
    }

    #[inline(always)]
    const fn from_id(id: ProbeId, stripe_mask: usize) -> Self {
        Self {
            home_stripe: id.raw & stripe_mask,
            group_phase: (id.mixed & 63) as u32,
            bit_phase: ((id.mixed >> 6) & 63) as u32,
            word_phase: ((id.mixed >> 12) & WORD_PHASE_MASK) as u32,
        }
    }

    #[inline(always)]
    const fn from_phase(home_stripe: usize, phase: u64) -> Self {
        Self {
            home_stripe,
            group_phase: (phase & 63) as u32,
            bit_phase: ((phase >> 6) & 63) as u32,
            word_phase: ((phase >> 12) & WORD_PHASE_MASK) as u32,
        }
    }

    #[inline(always)]
    const fn phase(self) -> u64 {
        self.group_phase as u64 | ((self.bit_phase as u64) << 6) | ((self.word_phase as u64) << 12)
    }

    #[inline(always)]
    const fn stripe(self, scanned: usize, stripe_mask: usize) -> usize {
        (self.home_stripe + scanned) & stripe_mask
    }

    #[inline(always)]
    const fn group(self, offset: usize, group_count: usize) -> usize {
        let start = (self.group_phase as usize * group_count) >> 6;
        let group = start + offset;
        if group >= group_count {
            group - group_count
        } else {
            group
        }
    }

    #[inline(always)]
    const fn select_group(self, groups: u64, group_count: usize) -> usize {
        let start = (self.group_phase as usize * group_count) >> 6;
        let rotated = groups.rotate_right(start as u32);
        ((rotated.trailing_zeros() as usize) + start) & (SLOT_WORD_BITS - 1)
    }

    #[inline(always)]
    const fn select_set_bit(self, word: u64) -> usize {
        let rotated = word.rotate_right(self.bit_phase);
        ((rotated.trailing_zeros() + self.bit_phase) & (SLOT_WORD_BITS as u32 - 1)) as usize
    }

    #[inline]
    const fn select_set_bits(self, word: u64, limit: usize) -> u64 {
        let mut remaining = word.rotate_right(self.bit_phase);
        let mut selected = 0u64;
        let mut taken = 0;

        while remaining != 0 && taken < limit {
            let bit = remaining.trailing_zeros();
            let mask = 1u64 << bit;
            selected |= mask;
            remaining &= !mask;
            taken += 1;
        }

        selected.rotate_left(self.bit_phase)
    }

    #[inline(always)]
    const fn select_ranked_bit(self, word: u64, rank: usize) -> usize {
        let mut rotated = word.rotate_right(self.bit_phase);
        let mut skipped = 0;
        while skipped < rank {
            rotated &= rotated - 1;
            skipped += 1;
        }
        ((rotated.trailing_zeros() + self.bit_phase) & (SLOT_WORD_BITS as u32 - 1)) as usize
    }
}

#[cfg(all(test, not(feature = "loom")))]
pub(super) mod tests {
    use super::*;
    use commonware_utils::{NZU32, NZUsize};
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize as StdAtomicUsize, Ordering as AtomicOrdering},
    };

    pub fn created(freelist: &Freelist) -> usize {
        freelist.created.load(Ordering::Relaxed)
    }

    pub fn len(freelist: &Freelist) -> usize {
        freelist
            .stripes
            .iter()
            .map(|stripe| {
                (0..stripe.logical_words)
                    .map(|word| stripe.leaf(word).load(Ordering::Acquire).count_ones() as usize)
                    .sum::<usize>()
            })
            .sum()
    }

    pub fn num_words(freelist: &Freelist) -> usize {
        freelist
            .stripes
            .iter()
            .map(|stripe| stripe.logical_words)
            .sum()
    }

    pub fn num_stripes(freelist: &Freelist) -> usize {
        freelist.stripes.len()
    }

    fn reserve_by_slot(freelist: &Freelist, capacity: usize) -> Vec<Option<PooledBuffer>> {
        let mut entries = (0..capacity).map(|_| None).collect::<Vec<_>>();
        for _ in 0..capacity {
            let buffer = freelist.try_create(false).expect("slot");
            let slot = buffer.slot() as usize;
            assert!(slot < capacity);
            assert!(entries[slot].replace(buffer).is_none());
        }
        entries
    }

    const TEST_LAYOUT: Layout = match Layout::from_size_align(64, 64) {
        Ok(layout) => layout,
        Err(_) => unreachable!(),
    };

    fn mapping_shell(base_chunk_words: usize) -> Freelist {
        Freelist {
            layout: TEST_LAYOUT,
            capacity: 0,
            created: CachePadded::new(AtomicUsize::new(0)),
            stripes: Vec::<CachePadded<Stripe>>::new().into_boxed_slice(),
            creation_cursors: Vec::<CachePadded<CreationCursor>>::new().into_boxed_slice(),
            stripe_mask: 0,
            stripe_shift: 0,
            base_chunk_words,
            base_chunk_shift: base_chunk_words.trailing_zeros(),
            summaries_enabled: true,
        }
    }

    fn mapping_stripe(capacity: usize, base_chunk_words: usize) -> Stripe {
        let logical_words = capacity.div_ceil(SLOT_WORD_BITS);
        let (group_count, single_groups, valid_group_mask) =
            group_geometry(logical_words, base_chunk_words, AVAILABILITY_BITS);
        Stripe {
            summary: AtomicU64::new(0),
            leaves: Vec::new().into_boxed_slice(),
            slots: Vec::new().into_boxed_slice(),
            capacity,
            logical_words,
            valid_group_mask,
            group_count,
            single_groups,
        }
    }

    #[test]
    fn test_geometry_bounds_stripes_for_capacity_and_parallelism() {
        let target = TARGET_MAX_SLOTS_PER_STRIPE;
        let cases = [
            (1, 1, 1),
            (3, 4, 2),
            (target - 1, 1, 1),
            (target, 1, 1),
            (target + 1, 1, 2),
            ((1usize << 29) - 1, 1, 32),
            (1usize << 29, 1, 32),
            ((1usize << 29) + 1, 1, 64),
            (1usize << 29, 16, 32),
            (1usize << 29, 64, 64),
            (1usize << 29, 1024, 1024),
            (1usize << 29, 4096, 4096),
            (8192, 4095, 4096),
            (8192, 4096, 4096),
            (8192, 4097, 4096),
            (u32::MAX as usize, 1, 256),
            (u32::MAX as usize, usize::MAX, 4096),
        ];

        for (capacity, parallelism, expected_stripes) in cases {
            let geometry = Geometry::new(capacity, parallelism);
            assert_eq!(geometry.stripe_count, expected_stripes);
            assert!(geometry.stripe_count.is_power_of_two());
            assert!(geometry.base_chunk_words <= 4096);
            for stripe in 0..geometry.stripe_count {
                let stripe_capacity = geometry.stripe_capacity(stripe);
                assert!(stripe_capacity <= target);
                let logical_words = stripe_capacity.div_ceil(SLOT_WORD_BITS);
                let base_chunks = logical_words.div_ceil(geometry.base_chunk_words);
                assert!(base_chunks <= 64);
                let (groups, _, mask) =
                    group_geometry(logical_words, geometry.base_chunk_words, AVAILABILITY_BITS);
                assert!(groups <= AVAILABILITY_BITS as u32);
                assert_eq!(mask & CODE_MASK, 0);
            }
        }
    }

    #[test]
    fn test_geometry_capacity_and_word_boundaries() {
        for (capacity, expected_words) in [(1, 1), (63, 1), (64, 1), (65, 2)] {
            let geometry = Geometry::new(capacity, 1);
            assert_eq!(geometry.max_logical_words, expected_words);
        }

        for words in [1, 63, 64, 65] {
            let capacity = (words - 1) * SLOT_WORD_BITS + 1;
            let geometry = Geometry::new(capacity, 1);
            assert_eq!(geometry.max_logical_words, words);
        }
    }

    #[test]
    fn test_geometry_counts_aggregate_leaf_blocks() {
        for blocks in [15, 16, 17, 31, 32, 33] {
            let capacity = blocks * LEAF_WORDS_PER_BLOCK * SLOT_WORD_BITS;
            let concentrated = Geometry::new(capacity, 1);
            assert_eq!(concentrated.total_leaf_blocks, blocks);

            let stripes = 1usize << blocks.ilog2();
            let extra_blocks = blocks - stripes;
            let scattered_capacity = stripes * LEAF_WORDS_PER_BLOCK * SLOT_WORD_BITS + extra_blocks;
            let scattered = Geometry::new(scattered_capacity, stripes);
            assert_eq!(scattered.stripe_count, stripes);
            assert_eq!(scattered.total_leaf_blocks, blocks);
        }
    }

    #[test]
    fn test_group_geometry_pairs_only_the_tail() {
        let cases = [
            (1, 1, 1),
            (57, 57, 57),
            (58, 58, 58),
            (59, 58, 57),
            (63, 58, 53),
            (64, 58, 52),
        ];

        for (base_chunks, expected_groups, expected_single) in cases {
            for logical_words in [base_chunks * 4, (base_chunks - 1) * 4 + 1] {
                let (groups, single, mask) = group_geometry(logical_words, 4, AVAILABILITY_BITS);
                assert_eq!(groups as usize, expected_groups);
                assert_eq!(single as usize, expected_single);
                assert_eq!(mask, low_bits(expected_groups));

                for base in 0..base_chunks {
                    let group = group_for_base(expected_single, base);
                    let (first, count) = group_base_range(expected_single, group);
                    assert!(base >= first && base < first + count);
                }
            }
        }
    }

    #[test]
    fn test_masks_codes_and_admission_boundaries() {
        assert_eq!(low_bits(64), u64::MAX);
        assert_eq!(encode_code(0), 0x0400_0000_0000_0000);
        assert_eq!(encode_code(57), 0xe800_0000_0000_0000);
        assert_eq!(decode_code(encode_code(0)), Some(0));
        assert_eq!(decode_code(encode_code(57)), Some(57));
        for group in 0..AVAILABILITY_BITS {
            let code = encode_code(group);
            assert_eq!(code & AVAILABILITY_MASK, 0);
            assert_eq!(decode_code(code), Some(group));
            assert_ne!(code, 0);
        }
        assert!(std::panic::catch_unwind(|| decode_code(59u64 << CODE_SHIFT)).is_err());
        assert_eq!(next_admission(usize::MAX, usize::MAX), None);
        assert_eq!(next_admission(usize::MAX - 1, usize::MAX), Some(usize::MAX));
    }

    #[test]
    fn test_cursor_encoding_and_group_major_bijection() {
        let phase = PROBE_PHASE_MASK;
        let next = 1 << 24;
        let state = encode_cursor(phase, next);
        assert_eq!(decode_cursor_phase(state), phase);
        assert_eq!(decode_cursor_next(state), next);

        let cursor = CreationCursor::new(0);
        assert_eq!(cursor.claim(phase, 2), Some((phase, 0)));
        assert_eq!(cursor.claim(0, 2), Some((phase, 1)));
        let full = cursor.state.load(Ordering::Relaxed);
        assert_eq!(cursor.claim(1, 2), None);
        assert_eq!(cursor.state.load(Ordering::Relaxed), full);

        for (capacity, max_groups) in [(1, 58), (65, 1), (130, 58), (257, 58)] {
            let set = Freelist::new_inner(
                NZU32!(capacity),
                NZUsize!(1),
                TEST_LAYOUT,
                false,
                ConstructionOptions {
                    force_summaries: true,
                    max_groups,
                },
            );
            let probe = Probe::from_id(
                ProbeId {
                    raw: 10,
                    mixed: mix_probe_id(10),
                },
                set.stripe_mask,
            );
            for stripe in set.stripes.iter() {
                let mut seen = vec![false; stripe.capacity];
                for ticket in 0..stripe.capacity {
                    let local = set.unrank_local(stripe, probe, ticket);
                    assert!(local < stripe.capacity);
                    assert!(!seen[local]);
                    seen[local] = true;
                }
                assert!(seen.into_iter().all(|seen| seen));
            }
        }
    }

    #[test]
    fn test_cursor_retains_unreduced_phase_across_group_widths() {
        let set = mapping_shell(4096);
        let stripe = mapping_stripe(1 << 24, 4096);
        assert_eq!(stripe.group_count, 58);
        assert_eq!(stripe.single_groups, 52);
        let probe = Probe::from_id(
            ProbeId {
                raw: 10,
                mixed: mix_probe_id(10),
            },
            31,
        );
        assert_eq!(probe.group(0, 58), 51);

        let (single_start, _, single_full) = set.group_word_range(&stripe, 51);
        assert_eq!(
            Freelist::word_offset(probe, single_full, Some(single_full)),
            800
        );
        let first = set.unrank_local(&stripe, probe, 0);
        assert_eq!(first / SLOT_WORD_BITS - single_start, 800);

        let (pair_start, _, pair_full) = set.group_word_range(&stripe, 52);
        assert_eq!(
            Freelist::word_offset(probe, pair_full, Some(pair_full)),
            4896
        );
        let first_pair_ticket = set.group_slot_count(&stripe, 51);
        let first_pair = set.unrank_local(&stripe, probe, first_pair_ticket);
        assert_eq!(first_pair / SLOT_WORD_BITS - pair_start, 4896);
    }

    #[test]
    fn test_fixed_probe_prefixes_remain_in_the_first_group() {
        let set = mapping_shell(4096);
        let stripe = mapping_stripe(1 << 24, 4096);
        for (raw, tickets) in [(10_567, 8), (684, 64)] {
            let probe = Probe::from_id(
                ProbeId {
                    raw,
                    mixed: mix_probe_id(raw as u64),
                },
                31,
            );
            let group = probe.group(0, stripe.group_count as usize);
            let (start, end, _) = set.group_word_range(&stripe, group);
            for ticket in 0..tickets {
                let local = set.unrank_local(&stripe, probe, ticket);
                assert!((start..end).contains(&(local / SLOT_WORD_BITS)));
            }
        }
    }

    #[test]
    fn test_freelist_try_create_tracks_capacity_and_prefill() {
        // Creation should reserve exactly the configured capacity, whether
        // slots are created lazily or during prefill.
        let set = Freelist::new(NZU32!(2), NZUsize!(1), TEST_LAYOUT, false);
        assert_eq!(created(&set), 0);

        // Without prefill, slots are reserved lazily as buffers are created.
        let buffer0 = set.try_create(false).expect("first creation");
        let buffer1 = set.try_create(false).expect("second creation");
        let slot0 = buffer0.slot();
        let slot1 = buffer1.slot();
        assert_ne!(slot0, slot1);
        assert!(slot0 < 2);
        assert!(slot1 < 2);
        assert_eq!(created(&set), 2);
        let debug = format!("{buffer0:?}");
        assert!(debug.contains("PooledBuffer"));
        assert!(debug.contains(&format!("slot: {slot0}")));

        // Slot reservation is bounded by capacity, even if the created
        // buffers have not yet been returned to the freelist.
        assert!(set.try_create(false).is_none());

        // Returning created buffers makes them available for reuse, but does
        // not reopen slot creation beyond the fixed capacity.
        set.put(buffer0);
        set.put(buffer1);
        assert_eq!(len(&set), 2);

        assert_eq!(created(&set), 2);
        assert!(set.try_create(false).is_none());

        // Prefill reserves and publishes every slot during construction. Use a
        // partial final logical row so unused high bits would show up as extra
        // free slots if the initialization mask were wrong.
        let prefilled = Freelist::new(NZU32!(10), NZUsize!(4), TEST_LAYOUT, true);
        assert_eq!(created(&prefilled), 10);
        assert_eq!(len(&prefilled), 10);
        assert!(prefilled.try_create(false).is_none());

        let mut seen = [false; 10];
        let mut taken = Vec::new();
        for _ in 0..10 {
            let buffer = prefilled.take().expect("prefilled slot");
            let slot = buffer.slot() as usize;
            assert!(slot < 10);
            assert!(!seen[slot]);
            seen[slot] = true;
            taken.push(buffer);
        }
        assert!(seen.into_iter().all(|seen| seen));
        assert!(prefilled.take().is_none());

        // Return taken test buffers so the freelist owns deallocation.
        for buffer in taken {
            prefilled.put(buffer);
        }
    }

    #[test]
    fn test_freelist_forced_summary_publishes_and_cleans() {
        let set = Freelist::new_forced_summary(NZU32!(2), NZUsize!(1), TEST_LAYOUT, false);
        assert!(set.summaries_enabled);
        let buffer = set.try_create(false).expect("slot");
        let slot = buffer.slot();
        set.put(buffer);

        let (stripe_index, _, word, _) = set.slot_location(slot);
        let stripe = &set.stripes[stripe_index];
        let group = set.group_for_word(stripe, word);
        assert_ne!(
            stripe.summary.load(Ordering::Acquire) & group_mask(group),
            0
        );

        let taken = set.take().expect("published slot");
        assert_eq!(taken.slot(), slot);
        assert!(set.take().is_none());
        assert_eq!(stripe.summary.load(Ordering::Acquire), 0);
        set.put(taken);
    }

    #[test]
    fn test_freelist_summary_batch_publication_and_overlap_panic() {
        let set = Freelist::new_forced_summary(NZU32!(3), NZUsize!(1), TEST_LAYOUT, false);
        let mut entries = reserve_by_slot(&set, 3);
        let first = entries[0].take().unwrap();
        let second = entries[1].take().unwrap();
        let first_slot = first.slot();

        // SAFETY: this duplicate exists only to exercise the post-publication
        // overlap assertion. The original handle is published first.
        let duplicate = unsafe { PooledBuffer::from_owner(set.slot_ptr(first_slot)) };
        set.put(first);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            set.put_batch([second, duplicate]);
        }));
        assert!(panic.is_err());

        let mut taken = Vec::new();
        assert_eq!(set.take_batch(3, |buffer| taken.push(buffer)), 2);
        let mut slots = taken.iter().map(PooledBuffer::slot).collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![0, 1]);
        for buffer in taken {
            set.put(buffer);
        }
        for buffer in entries.into_iter().flatten() {
            set.put(buffer);
        }
    }

    #[test]
    fn test_freelist_summary_code_observer_repairs_before_claim() {
        let set = Freelist::new_forced_summary(NZU32!(1), NZUsize!(1), TEST_LAYOUT, false);
        let buffer = set.try_create(false).expect("slot");
        let stripe = &set.stripes[0];

        // Seed the constructor-exclusive state that an active cleaner exposes.
        stripe.leaf(0).store(1, Ordering::Relaxed);
        stripe.summary.store(encode_code(0), Ordering::Relaxed);
        let taken = set.take().expect("code observer must scan the named group");
        assert_eq!(taken.slot(), buffer.slot());
        let state = stripe.summary.load(Ordering::Acquire);
        assert_ne!(state & group_mask(0), 0);
        assert_eq!(decode_code(state), Some(0));

        // This test seeded a code without an owner, so remove it explicitly.
        stripe
            .summary
            .fetch_and(AVAILABILITY_MASK, Ordering::Release);
        set.put(taken);
    }

    #[test]
    fn test_freelist_cleanup_guard_restores_navigation_on_unwind() {
        let summary = AtomicU64::new(encode_code(0) | group_mask(1));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = CleanupGuard::new(&summary, group_mask(0));
            panic!("injected cleanup failure");
        }));
        assert!(panic.is_err());
        assert_eq!(
            summary.load(Ordering::Acquire),
            group_mask(0) | group_mask(1)
        );
    }

    #[test]
    fn test_freelist_drain_leaves_summary_state_unchanged() {
        let set = Freelist::new_forced_summary(NZU32!(2), NZUsize!(1), TEST_LAYOUT, true);
        let before = set.stripes[0].summary.load(Ordering::Acquire);
        assert_ne!(before, 0);
        assert_eq!(set.drain(), 2);
        assert_eq!(set.stripes[0].summary.load(Ordering::Acquire), before);
        assert!(set.take().is_none());
        assert_eq!(set.stripes[0].summary.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_freelist_forced_pair_group_reaches_both_chunks() {
        let set = Freelist::new_inner(
            NZU32!(65),
            NZUsize!(1),
            TEST_LAYOUT,
            false,
            ConstructionOptions {
                force_summaries: true,
                max_groups: 1,
            },
        );
        assert_eq!(set.stripes[0].group_count, 1);
        assert_eq!(set.stripes[0].single_groups, 0);
        let mut entries = reserve_by_slot(&set, 65);
        set.put(entries[64].take().expect("second chunk slot"));
        let taken = set.take().expect("paired group must reach its tail chunk");
        assert_eq!(taken.slot(), 64);
        set.put(taken);
        for buffer in entries.into_iter().flatten() {
            set.put(buffer);
        }
    }

    #[test]
    #[should_panic(expected = "returned slot must not already be marked free")]
    fn test_freelist_put_rejects_double_return() {
        let set = Freelist::new(NZU32!(1), NZUsize!(1), TEST_LAYOUT, false);
        let buffer = set.try_create(false).expect("slot available");
        // SAFETY: the duplicate handle exists only to drive the double-return
        // assert. The second put panics before it is used further, and drain
        // deallocates the slot exactly once afterwards.
        let duplicate = unsafe { PooledBuffer::from_owner(set.slot_ptr(0)) };
        set.put(buffer);
        set.put(duplicate);
    }

    #[test]
    #[should_panic(expected = "returned slot batch must not already contain a free slot")]
    fn test_freelist_put_batch_rejects_double_return() {
        // Two entries force the multi-entry `put_entries` path, whose per-word
        // assert is separate from the single-buffer `put` assert.
        let set = Freelist::new(NZU32!(2), NZUsize!(1), TEST_LAYOUT, false);
        let returned = set.try_create(false).expect("returned slot");
        let returned_slot = returned.slot();
        let other = set.try_create(false).expect("other slot");

        // SAFETY: the duplicate handle exists only to drive the batch
        // double-return assert. put_batch panics before it is used further,
        // and drain deallocates each slot exactly once afterwards.
        let duplicate = unsafe { PooledBuffer::from_owner(set.slot_ptr(returned_slot)) };
        set.put(returned);
        set.put_batch([other, duplicate]);
    }

    #[test]
    fn test_freelist_put_batch_rejects_duplicate_within_batch() {
        // A duplicate inside one batch trips the staging assert before any
        // bit is published. The panic is caught (instead of should_panic) so
        // the staged-but-unpublished slot can be republished afterwards:
        // leaking it is the documented panic behavior, but it would trip
        // miri's leak check.
        let set = Freelist::new(NZU32!(2), NZUsize!(1), TEST_LAYOUT, false);
        let buffer = set.try_create(false).expect("slot available");
        let slot = buffer.slot();

        // SAFETY: the duplicate handle exists only to drive the staging
        // assert. put_batch panics before publishing either handle.
        let duplicate = unsafe { PooledBuffer::from_owner(set.slot_ptr(slot)) };
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            set.put_batch([buffer, duplicate]);
        }))
        .expect_err("duplicate slot must panic");
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(
            message.contains("duplicate slot in put_batch"),
            "unexpected panic: {message}"
        );

        // Republish the slot so teardown reclaims its allocation.
        // SAFETY: `slot` was created by this freelist and is not available
        // (the staging panic happened before its bit was inserted).
        set.put(unsafe { PooledBuffer::from_owner(set.slot_ptr(slot)) });
    }

    #[test]
    fn test_freelist_returns_each_slot_once() {
        // Use a non-power-of-two capacity to cover partial final words while
        // keeping the expected slot set easy to inspect.
        let set = Freelist::new(NZU32!(3), NZUsize!(1), TEST_LAYOUT, false);

        let buffer0 = set.try_create(false).unwrap();
        let buffer1 = set.try_create(false).unwrap();
        let buffer2 = set.try_create(false).unwrap();
        let mut created = [buffer0.slot(), buffer1.slot(), buffer2.slot()];
        created.sort_unstable();
        assert_eq!(created, [0, 1, 2]);
        set.put(buffer0);
        set.put(buffer1);
        set.put(buffer2);

        // Every free slot should be returned exactly once, and the
        // freelist should report empty afterward.
        let mut seen = [false; 3];
        let mut taken = Vec::new();
        for _ in 0..3 {
            let buffer = set.take().expect("slot should be available");
            let slot = buffer.slot();
            assert!(!seen[slot as usize]);
            seen[slot as usize] = true;
            taken.push(buffer);
        }

        assert_eq!(len(&set), 0);
        assert!(seen.into_iter().all(|seen| seen));
        assert!(set.take().is_none());

        // Return taken test buffers so the freelist owns deallocation.
        for buffer in taken {
            set.put(buffer);
        }
    }

    #[test]
    fn test_freelist_try_create_uses_thread_probe_order() {
        // Lazy creation follows the same group, word, and bit phases as reuse.
        let set = Freelist::new(NZU32!(512), NZUsize!(8), TEST_LAYOUT, false);
        let probe = Probe::new(set.stripe_mask);
        let stripe_index = probe.home_stripe;
        let stripe = &set.stripes[stripe_index];

        let expected0 = set.slot_index(stripe_index, set.unrank_local(stripe, probe, 0));
        let expected1 = set.slot_index(stripe_index, set.unrank_local(stripe, probe, 1));

        // The first two cursor tickets use that exact order.
        let buffer0 = set.try_create(false).expect("first probed slot");
        let buffer1 = set.try_create(false).expect("second probed slot");
        let slot0 = buffer0.slot();
        let slot1 = buffer1.slot();
        assert_eq!(slot0, expected0);
        assert_eq!(slot1, expected1);

        // Return the created buffers so the freelist owns deallocation.
        set.put(buffer0);
        set.put(buffer1);
    }

    #[test]
    fn test_freelist_concurrent_try_create_reserves_unique_slots() {
        // Multiple creators racing to grow the same size class must reserve
        // every slot at most once and stop exactly at capacity.
        const CAPACITY: usize = 128;

        // Cover capacity-wide creation with real threads. The Loom sibling
        // exhaustively covers same-candidate reservation races.
        let set = Arc::new(Freelist::new(NZU32!(128), NZUsize!(16), TEST_LAYOUT, false));
        let barrier = Arc::new(Barrier::new(16));
        let (tx, rx) = std::sync::mpsc::channel();
        let mut handles = Vec::new();

        for _ in 0..16 {
            let set = Arc::clone(&set);
            let barrier = Arc::clone(&barrier);
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                // Align creators so admission and stripe cursors see real RMW
                // contention instead of serial thread startup.
                barrier.wait();
                let mut entries = Vec::new();
                while let Some(entry) = set.try_create(false) {
                    entries.push(entry);
                }
                tx.send(entries).expect("send created entries");
            }));
        }
        drop(tx);

        let mut entries = Vec::new();
        let mut seen = vec![false; CAPACITY];
        for thread_entries in rx {
            for buffer in thread_entries {
                // Each successful reservation must be within capacity and must
                // be observed exactly once across all racing creators.
                let slot = buffer.slot() as usize;
                assert!(slot < CAPACITY);
                assert!(!seen[slot]);
                seen[slot] = true;
                entries.push(buffer);
            }
        }

        for handle in handles {
            handle.join().expect("creator should not panic");
        }

        // Capacity should be exhausted exactly once: no missing slots, no
        // duplicate reservations, and the created counter reflects the total.
        assert_eq!(entries.len(), CAPACITY);
        assert!(seen.into_iter().all(|seen| seen));
        assert_eq!(created(&set), CAPACITY);

        // Return every created buffer so the freelist owns deallocation.
        for buffer in entries {
            set.put(buffer);
        }
    }

    #[test]
    fn test_freelist_uses_bounded_power_of_two_stripes() {
        let cases = [
            (1, 1, 1),
            (2, 2, 2),
            (3, 4, 2),
            (4, 4, 4),
            (12, 9, 8),
            (16, 8, 8),
            (64, 8, 8),
            (512, 8, 8),
            (513, 8, 8),
            (4097, 8, 8),
        ];

        for (capacity, parallelism, expected_stripes) in cases {
            let set = Freelist::new(NZU32!(capacity), NZUsize!(parallelism), TEST_LAYOUT, false);
            assert_eq!(num_stripes(&set), expected_stripes);
            assert!(num_stripes(&set).is_power_of_two());

            for slot in 0..capacity {
                let (stripe, local, word, mask) = set.slot_location(slot);
                assert!(stripe < expected_stripes);
                assert!(word < set.stripes[stripe].logical_words);
                assert_ne!(mask, 0);
                assert_eq!(set.slot_index(stripe, local), slot);
            }

            for (stripe_index, stripe) in set.stripes.iter().enumerate() {
                assert_eq!(stripe.slots.len(), stripe.capacity);
                for local in 0..stripe.capacity {
                    let slot = set.slot_index(stripe_index, local);
                    assert_eq!(set.slot_ptr(slot), set.owner_ptr(stripe_index, local));
                }
            }
        }
    }

    #[test]
    fn test_freelist_put_batch_handles_empty_single_and_multi_entry_paths() {
        // Exercise all batch insertion paths while keeping ownership explicit:
        // empty no-op, single-entry delegation, and multi-entry coalescing.
        let set = Freelist::new(NZU32!(8), NZUsize!(8), TEST_LAYOUT, false);

        // Empty batches are a no-op and must not make anything available.
        set.put_batch(Vec::new());
        assert_eq!(len(&set), 0);

        // Reserve the full slot range.
        let mut created = reserve_by_slot(&set, 8);

        // A single-entry batch delegates to `put`, preserving the cheaper
        // one-buffer path.
        let buffer = created[3].take().unwrap();
        set.put_batch(vec![buffer]);
        assert_eq!(len(&set), 1);

        let mut taken = Vec::new();
        assert_eq!(set.take_batch(1, |buffer| taken.push(buffer)), 1);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].slot(), 3);
        let single = taken.pop().expect("single entry was taken");

        // Multi-entry batches should make every slot available and preserve
        // ownership of each returned buffer until it is taken.
        let mut batch = Vec::new();
        for slot in [1, 5, 7] {
            let buffer = created[slot as usize].take().unwrap();
            batch.push(buffer);
        }
        set.put_batch(batch);
        assert_eq!(len(&set), 3);

        assert_eq!(set.take_batch(3, |buffer| taken.push(buffer)), 3);
        let mut slots = taken.iter().map(PooledBuffer::slot).collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![1, 5, 7]);
        assert_eq!(len(&set), 0);

        // Return taken test buffers so the freelist owns deallocation.
        set.put(single);
        for buffer in taken {
            set.put(buffer);
        }
        for buffer in created.into_iter().flatten() {
            set.put(buffer);
        }
    }

    #[test]
    fn test_freelist_put_batch_uses_sparse_records_for_large_leaf_layout() {
        let set = Freelist::new(NZU32!(8193), NZUsize!(65), TEST_LAYOUT, false);
        assert!(set.stripes.len() * set.stripes[0].logical_words > INLINE_LEAF_MASKS);
        assert!(num_words(&set) > INLINE_LEAF_MASKS);

        // Reserve all slots so the sparse test slots are valid while only
        // those slots are published to the freelist.
        let mut created = reserve_by_slot(&set, 8193);

        let mut batch = Vec::new();
        for slot in [0, 1, 64, 8192] {
            let buffer = created[slot as usize].take().expect("slot buffer");
            batch.push(buffer);
        }
        set.put_batch(batch);
        assert_eq!(len(&set), 4);

        let mut taken = Vec::new();
        assert_eq!(set.take_batch(8, |buffer| taken.push(buffer)), 4);
        let mut slots = taken.iter().map(PooledBuffer::slot).collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![0, 1, 64, 8192]);
        assert_eq!(len(&set), 0);

        // Return taken test buffers so the freelist owns deallocation.
        for buffer in taken {
            set.put(buffer);
        }
        for buffer in created.into_iter().flatten() {
            set.put(buffer);
        }
    }

    #[test]
    fn test_freelist_drain_returns_all_available_slots() {
        // Drain should drop every globally available buffer while leaving
        // outstanding created buffers owned by the caller.
        let set = Freelist::new(NZU32!(4), NZUsize!(4), TEST_LAYOUT, false);
        let mut entries = (0..4)
            .map(|_| set.try_create(false).expect("slot"))
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 4);
        let held = entries.pop().expect("held entry");
        for buffer in entries {
            set.put(buffer);
        }

        assert_eq!(set.drain(), 3);
        assert_eq!(len(&set), 0);

        // Return taken test buffer so the freelist owns deallocation.
        set.put(held);
    }

    #[test]
    fn test_freelist_take_batch_handles_zero_single_and_partial_fill() {
        // Put fewer slots than the largest requested batch to cover exact,
        // partial, and empty refill behavior in one setup.
        let set = Freelist::new(NZU32!(4), NZUsize!(4), TEST_LAYOUT, false);
        for _ in [0, 1, 2] {
            let buffer = set.try_create(false).expect("slot");
            set.put(buffer);
        }

        let mut taken = Vec::new();
        let mut record = |buffer| taken.push(buffer);

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

        let mut slots = taken.iter().map(PooledBuffer::slot).collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots.len(), 3);
        assert!(slots.iter().all(|&slot| slot < 4));
        slots.dedup();
        assert_eq!(slots.len(), 3);

        // Return taken test buffers so the freelist owns deallocation.
        for buffer in taken {
            set.put(buffer);
        }
    }

    #[test]
    fn test_freelist_take_batch_breaks_after_filling_target_in_home_word() {
        let set = Freelist::new(NZU32!(16), NZUsize!(8), TEST_LAYOUT, true);
        let home = Probe::new(set.stripe_mask).home_stripe;
        let slot0 = set.slot_index(home, 0);
        let slot1 = set.slot_index(home, 1);

        // A two-slot batch should fill from this thread's first probed word
        // and stop immediately.
        let mut taken = Vec::new();
        assert_eq!(set.take_batch(2, |buffer| taken.push(buffer)), 2);

        let mut slots = taken.iter().map(PooledBuffer::slot).collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(slots, vec![slot0, slot1]);
        assert_eq!(len(&set), 14);

        // Return taken test buffers so the freelist owns deallocation.
        for buffer in taken {
            set.put(buffer);
        }
    }

    #[test]
    fn test_freelist_take_batch_stops_mid_word_when_limit_is_reached() {
        let set = Freelist::new(NZU32!(24), NZUsize!(8), TEST_LAYOUT, true);
        let home = Probe::new(set.stripe_mask).home_stripe;
        // This thread's first probed word contains three slots, so the batch
        // claim has to stop after clearing only the requested number of bits.
        let slots = [
            set.slot_index(home, 0),
            set.slot_index(home, 1),
            set.slot_index(home, 2),
        ];

        let mut taken = Vec::new();
        assert_eq!(set.take_batch(2, |buffer| taken.push(buffer)), 2);
        assert_eq!(len(&set), 22);

        // The third slot should remain free and be retrievable normally.
        let remaining = set.take().expect("one slot should remain free");
        let mut seen = taken.iter().map(PooledBuffer::slot).collect::<Vec<_>>();
        seen.push(remaining.slot());
        seen.sort_unstable();
        assert_eq!(seen, slots);

        // Return taken test buffers so the freelist owns deallocation.
        for buffer in taken {
            set.put(buffer);
        }
        set.put(remaining);
    }

    #[test]
    fn test_probe_selectors_respect_phase_and_limit() {
        // The probe offset should rotate priority without selecting bits that
        // are not present in the original word.
        let word = (1u64 << 1) | (1u64 << 5) | (1u64 << 9) | (1u64 << 20);

        let probe_0 = Probe {
            home_stripe: 0,
            group_phase: 0,
            word_phase: 0,
            bit_phase: 0,
        };
        let probe_6 = Probe {
            bit_phase: 6,
            ..probe_0
        };

        assert_eq!(probe_0.select_set_bit(word), 1);
        assert_eq!(probe_6.select_set_bit(word), 9);

        let selected = probe_6.select_set_bits(word, 2);
        // Starting after bit 6, the first two set bits are 9 and 20.
        assert_eq!(selected.count_ones(), 2);
        assert_eq!(selected & !word, 0);
        assert_eq!(selected, (1u64 << 9) | (1u64 << 20));

        let probe_32 = Probe {
            bit_phase: 32,
            ..probe_0
        };
        let wrap_word = (1u64 << 4) | (1u64 << 40);
        let selected = probe_32.select_set_bits(wrap_word, 2);
        // Starting after bit 32, selection should wrap after taking bit 40.
        assert_eq!(selected, wrap_word);
    }

    #[test]
    fn test_probe_mixer_vectors_and_fields() {
        let vectors = [
            (0, 0x0000_0000_0000_0000),
            (1, 0x5692_161d_100b_05e5),
            (10, 0x075c_8519_a932_0579),
            (32, 0xadfb_1ebb_497f_ad45),
            (33, 0xb494_1eef_8208_68c7),
            (u32::MAX as u64, 0x8b32_c408_e8c2_c97c),
            (u64::MAX, 0xb4d0_55fc_f2cb_bd7b),
        ];
        for (id, expected) in vectors {
            assert_eq!(mix_probe_id(id), expected);
        }

        let id = ProbeId {
            raw: 33,
            mixed: mix_probe_id(33),
        };
        let probe = Probe::from_id(id, 31);
        assert_eq!(probe.home_stripe, 1);
        assert!(probe.group_phase < 64);
        assert!(probe.bit_phase < 64);
        assert!((probe.word_phase as u64) < (1 << WORD_PHASE_BITS));
        assert_eq!(Probe::from_phase(1, probe.phase()).phase(), probe.phase());

        let mut wrapped = (0..32)
            .map(|offset| probe.stripe(offset, 31))
            .collect::<Vec<_>>();
        wrapped.sort_unstable();
        assert_eq!(wrapped, (0..32).collect::<Vec<_>>());

        let wrapped_id = Probe::from_id(
            ProbeId {
                raw: usize::MAX,
                mixed: mix_probe_id(usize::MAX as u64),
            },
            31,
        );
        assert_eq!(wrapped_id.home_stripe, usize::MAX & 31);
    }

    #[test]
    fn test_freelist_take_retries_after_losing_a_same_bit_race() {
        // Force repeated same-word contention on a single free slot. Some
        // contenders should observe a stale non-zero word and follow the retry
        // path before discovering that another thread already claimed the slot.
        for _ in 0..32 {
            let set = Arc::new(Freelist::new(NZU32!(1), NZUsize!(1), TEST_LAYOUT, false));
            let buffer = set.try_create(false).unwrap();
            assert_eq!(buffer.slot(), 0);
            set.put(buffer);

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
            set.put(claimed);
        }
    }

    #[test]
    fn test_freelist_drop_drains_remaining_buffers() {
        // Dropping a non-empty freelist must drop any buffers still parked in
        // globally free slots.
        let set = Freelist::new(NZU32!(2), NZUsize!(2), TEST_LAYOUT, false);
        for _ in [0, 1] {
            let buffer = set.try_create(false).expect("slot");
            set.put(buffer);
        }
        drop(set);
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use commonware_utils::{NZU32, NZUsize, sync::Mutex};
    use loom::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
    };

    /// Tracked stand-ins for the non-atomic side-table state that bitmap
    /// publication transfers between threads.
    ///
    /// The real side-table accesses escape loom's tracking (they go through
    /// raw pointers extracted from the slot cells), so the publication models
    /// write these cells before `put` and read them after a claim: weakening
    /// the put-Release or take-Acquire edge makes loom report a data race
    /// here, which the slot-accounting assertions alone cannot detect.
    struct SlotStamps {
        cells: Vec<UnsafeCell<usize>>,
    }

    // SAFETY: cross-thread access is what the stamps exist to check. Loom
    // tracks every access made through `UnsafeCell::with`/`with_mut`.
    unsafe impl Send for SlotStamps {}
    // SAFETY: as above.
    unsafe impl Sync for SlotStamps {}

    impl SlotStamps {
        fn new(slots: usize) -> Arc<Self> {
            Arc::new(Self {
                cells: (0..slots).map(|_| UnsafeCell::new(0)).collect(),
            })
        }

        /// Stamps a slot before its owner publishes it.
        fn write(&self, slot: u32) {
            // SAFETY: the slot is owned by the stamping thread until `put`
            // publishes it. Loom flags any racing access.
            self.cells[slot as usize].with_mut(|cell| unsafe { *cell = 1 });
        }

        /// Asserts a claimed slot's stamp is visible to the claimant.
        fn assert_visible(&self, slot: u32) {
            // SAFETY: claiming the bit transfers slot ownership. Loom flags
            // the read as racing if the publication edge is too weak.
            self.cells[slot as usize].with(|cell| assert_eq!(unsafe { *cell }, 1));
        }
    }

    // This module uses loom to model the freelist's ownership protocol between
    // bitmap bits and side-table slots: a producer publishes a returned slot,
    // and exactly one consumer clears that bit before rebuilding a buffer
    // handle from the slot.
    // The models keep capacities small so loom can exhaustively explore the
    // interleavings that stress this protocol: same-word RMW composition,
    // striped scans across independent bitmap words, stale relaxed candidate
    // loads, and the Release/Acquire edge that transfers slot ownership after
    // its bit is claimed. Geometry-matrix tests cover single-word/single-bit,
    // single-word/multi-bit, multi-word/single-bit, and multi-word/multi-bit
    // layouts so both degenerate and striped cases stay exercised.

    fn single_word_freelist(capacity: u32) -> Freelist {
        let layout = Layout::from_size_align(64, 64).unwrap();
        Freelist::new(NZU32!(capacity), NZUsize!(1), layout, false)
    }

    fn forced_summary_freelist(capacity: u32) -> Freelist {
        let layout = Layout::from_size_align(64, 64).unwrap();
        Freelist::new_forced_summary(NZU32!(capacity), NZUsize!(1), layout, false)
    }

    // Performs the authoritative half of a put and leaves its summary
    // publication pending. `PooledBuffer` has no drop glue, so the set leaf
    // owns the allocation when this helper returns.
    fn stall_put_after_leaf(freelist: &Freelist, buffer: PooledBuffer) -> (usize, u64) {
        let (stripe_index, _, word, mask) = freelist.slot_location(buffer.slot());
        let stripe = &freelist.stripes[stripe_index];
        let previous = stripe.leaf(word).fetch_or(mask, Ordering::Release);
        assert_eq!(previous & mask, 0);
        (
            stripe_index,
            group_mask(freelist.group_for_word(stripe, word)),
        )
    }

    #[test]
    fn summary_starts_after_completed_publication_uses_exact_code() {
        loom::model(|| {
            let set = Arc::new(forced_summary_freelist(1));
            let buffer = set.try_create(false).expect("slot");
            let producer = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put(buffer))
            };
            producer.join().unwrap();

            let stripe = &set.stripes[0];
            let group = group_mask(0);
            assert_ne!(stripe.leaf(0).load(Ordering::Acquire), 0);
            assert_eq!(
                stripe.summary.compare_exchange(
                    group,
                    encode_code(0),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ),
                Ok(group)
            );

            // The take starts after the producer joins. No competing operation
            // can clear the published leaf, so an empty pass would leave that
            // completed publication set throughout the pass.
            let taker = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.take())
            };
            let buffer = taker
                .join()
                .unwrap()
                .expect("the exact code must preserve starts-after visibility");
            assert_eq!(buffer.slot(), 0);

            let state = stripe.summary.load(Ordering::Acquire);
            assert_eq!(state & group, group);
            assert_eq!(decode_code(state), Some(0));
            stripe
                .summary
                .fetch_and(AVAILABILITY_MASK, Ordering::Release);
            set.put(buffer);
        });
    }

    #[test]
    fn summary_second_put_publishes_while_first_is_delayed() {
        loom::model(|| {
            let set = Arc::new(forced_summary_freelist(2));
            let mut entries = Leases::entries(&set);
            let second_buffer = entries.pop().unwrap();
            let delayed_buffer = entries.pop().unwrap();
            assert!(entries.pop().is_none());

            let (leaf_ready_tx, leaf_ready_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let delayed = {
                let set = Arc::clone(&set);
                thread::spawn(move || {
                    let (_, group) = stall_put_after_leaf(&set, delayed_buffer);
                    leaf_ready_tx.send(group).unwrap();
                    resume_rx.recv().unwrap();
                    set.stripes[0].summary.fetch_or(group, Ordering::Release);
                })
            };

            let group = leaf_ready_rx.recv().unwrap();
            assert_eq!(set.stripes[0].summary.load(Ordering::Acquire), 0);

            let second = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put(second_buffer))
            };
            second.join().unwrap();
            assert_eq!(
                set.stripes[0].summary.load(Ordering::Acquire) & group,
                group
            );

            // Both slots share one leaf. The second put must publish the group
            // even though the first put already made that leaf nonzero.
            let expected = 0b11;
            let seen = AtomicUsize::new(0);
            let leases = Leases::new(Arc::clone(&set));
            assert_eq!(
                set.take_batch(2, |buffer| {
                    leases.push_expected(&seen, expected, buffer)
                }),
                2
            );
            assert_eq!(seen.load(Ordering::Relaxed), expected);

            resume_tx.send(()).unwrap();
            delayed.join().unwrap();
            assert!(set.take().is_none());
            assert_eq!(set.stripes[0].summary.load(Ordering::Acquire), 0);
        });
    }

    #[test]
    fn summary_competing_takes_clean_one_stale_group() {
        loom::model(|| {
            let set = Arc::new(forced_summary_freelist(1));
            let group = group_mask(0);
            set.stripes[0].summary.fetch_or(group, Ordering::Release);

            let completed = Arc::new(AtomicUsize::new(0));
            let mut takers = Vec::new();
            for _ in 0..2 {
                takers.push(thread::spawn({
                    let set = Arc::clone(&set);
                    let completed = Arc::clone(&completed);
                    move || {
                        assert!(set.take().is_none());
                        completed.fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }

            for taker in takers {
                taker.join().unwrap();
            }
            assert_eq!(completed.load(Ordering::Relaxed), 2);
            assert_eq!(set.stripes[0].summary.load(Ordering::Acquire), 0);
        });
    }

    #[test]
    fn summary_code_observer_repairs_before_claim_callback() {
        loom::model(|| {
            let set = forced_summary_freelist(1);
            let buffer = set.try_create(false).expect("slot");
            set.put(buffer);

            let stripe = &set.stripes[0];
            let group = group_mask(0);
            assert_eq!(
                stripe.summary.compare_exchange(
                    group,
                    encode_code(0),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ),
                Ok(group)
            );

            let mut claimed = None;
            assert_eq!(
                set.take_batch(1, |buffer| {
                    let state = stripe.summary.load(Ordering::Acquire);
                    assert_eq!(state & group, group);
                    assert_eq!(decode_code(state), Some(0));
                    claimed = Some(buffer);
                }),
                1
            );

            stripe
                .summary
                .fetch_and(AVAILABILITY_MASK, Ordering::Release);
            set.put(claimed.expect("observer must claim the coded group"));
        });
    }

    #[test]
    fn summary_batch_publication_races_take() {
        loom::model(|| {
            let set = Arc::new(forced_summary_freelist(2));
            let entries = Leases::entries(&set);
            let leases = Leases::new(Arc::clone(&set));
            let stamps = SlotStamps::new(2);
            let seen = Arc::new(AtomicUsize::new(0));
            let expected = 0b11;

            let writer = {
                let set = Arc::clone(&set);
                let stamps = Arc::clone(&stamps);
                thread::spawn(move || {
                    for entry in &entries {
                        stamps.write(entry.slot());
                    }
                    set.put_batch(entries);
                })
            };
            let taker = {
                let set = Arc::clone(&set);
                let leases = Arc::clone(&leases);
                let stamps = Arc::clone(&stamps);
                let seen = Arc::clone(&seen);
                thread::spawn(move || {
                    if let Some(buffer) = set.take() {
                        stamps.assert_visible(buffer.slot());
                        leases.push_expected(&seen, expected, buffer);
                    }
                })
            };

            writer.join().unwrap();
            taker.join().unwrap();
            while let Some(buffer) = set.take() {
                stamps.assert_visible(buffer.slot());
                leases.push_expected(&seen, expected, buffer);
            }

            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(set.stripes[0].summary.load(Ordering::Acquire), 0);
        });
    }

    #[test]
    fn summary_batch_publication_races_stale_group_cleanup() {
        loom::model(|| {
            let set = Arc::new(forced_summary_freelist(2));
            let entries = Leases::entries(&set);
            let leases = Leases::new(Arc::clone(&set));
            let seen = Arc::new(AtomicUsize::new(0));
            let expected = 0b11;
            let group = group_mask(0);

            // Make cleanup eligible before the batch starts. Loom can then
            // place the one-shot cleanup CAS before, between, or after the
            // batch's leaf publications and its final summary publication.
            set.stripes[0].summary.fetch_or(group, Ordering::Release);

            let writer = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put_batch(entries))
            };
            let taker = {
                let set = Arc::clone(&set);
                let leases = Arc::clone(&leases);
                let seen = Arc::clone(&seen);
                thread::spawn(move || {
                    set.take_batch(2, |buffer| leases.push_expected(&seen, expected, buffer));
                })
            };

            writer.join().unwrap();
            taker.join().unwrap();
            while let Some(buffer) = set.take() {
                leases.push_expected(&seen, expected, buffer);
            }

            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(set.stripes[0].summary.load(Ordering::Acquire), 0);
        });
    }

    #[test]
    fn summary_code_owner_repairs_and_clears_before_callback() {
        loom::model(|| {
            let set = Arc::new(forced_summary_freelist(1));
            let buffer = set.try_create(false).expect("slot");
            let group = group_mask(0);
            let stripe = &set.stripes[0];
            stripe.summary.fetch_or(group, Ordering::Release);
            assert_eq!(
                stripe.summary.compare_exchange(
                    group,
                    encode_code(0),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ),
                Ok(group)
            );

            let (leaf_ready_tx, leaf_ready_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let publisher = {
                let set = Arc::clone(&set);
                thread::spawn(move || {
                    let (_, published_group) = stall_put_after_leaf(&set, buffer);
                    leaf_ready_tx.send(published_group).unwrap();
                    resume_rx.recv().unwrap();
                    set.stripes[0]
                        .summary
                        .fetch_or(published_group, Ordering::Release);
                })
            };

            assert_eq!(leaf_ready_rx.recv().unwrap(), group);
            let mut claimed = None;
            {
                let mut on_entry = |buffer| {
                    let state = stripe.summary.load(Ordering::Acquire);
                    assert_eq!(state & group, group);
                    assert_eq!(decode_code(state), None);
                    claimed = Some(buffer);
                };
                let mut context = TakeContext {
                    max: 1,
                    filled: 0,
                    on_entry: &mut on_entry,
                };
                set.clean_owned_group(0, stripe, 0, Probe::from_phase(0, 0), &mut context);
                assert_eq!(context.filled, 1);
            }

            resume_tx.send(()).unwrap();
            publisher.join().unwrap();
            set.put(claimed.expect("the code owner must claim the published leaf"));
        });
    }

    #[test]
    fn summary_code_observers_losing_one_candidate_deliver_once() {
        loom::model(|| {
            let set = Arc::new(forced_summary_freelist(1));
            let buffer = set.try_create(false).expect("slot");
            set.put(buffer);

            let stripe = &set.stripes[0];
            let group = group_mask(0);
            assert_eq!(
                stripe.summary.compare_exchange(
                    group,
                    encode_code(0),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ),
                Ok(group)
            );

            let leases = Leases::new(Arc::clone(&set));
            let seen = Arc::new(AtomicUsize::new(0));
            let mut takers = Vec::new();
            for _ in 0..2 {
                takers.push(thread::spawn({
                    let set = Arc::clone(&set);
                    let leases = Arc::clone(&leases);
                    let seen = Arc::clone(&seen);
                    move || {
                        set.take_batch(1, |buffer| {
                            let state = set.stripes[0].summary.load(Ordering::Acquire);
                            assert_eq!(state & group, group);
                            assert_eq!(decode_code(state), Some(0));
                            leases.push_expected(&seen, 1, buffer);
                        });
                    }
                }));
            }
            for taker in takers {
                taker.join().unwrap();
            }

            assert_eq!(seen.load(Ordering::Relaxed), 1);
            assert_eq!(stripe.summary.load(Ordering::Acquire) & group, group);
            stripe
                .summary
                .fetch_and(AVAILABILITY_MASK, Ordering::Release);
        });
    }

    #[test]
    fn summary_code_observer_and_drain_conserve_the_leaf() {
        loom::model(|| {
            let set = Arc::new(forced_summary_freelist(1));
            let buffer = set.try_create(false).expect("slot");
            set.put(buffer);

            let stripe = &set.stripes[0];
            let group = group_mask(0);
            assert_eq!(
                stripe.summary.compare_exchange(
                    group,
                    encode_code(0),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ),
                Ok(group)
            );

            let leases = Leases::new(Arc::clone(&set));
            let taken = Arc::new(AtomicUsize::new(0));
            let drained = Arc::new(AtomicUsize::new(0));
            let taker = {
                let set = Arc::clone(&set);
                let leases = Arc::clone(&leases);
                let taken = Arc::clone(&taken);
                thread::spawn(move || {
                    set.take_batch(1, |buffer| {
                        let state = set.stripes[0].summary.load(Ordering::Acquire);
                        assert_eq!(state & group, group);
                        assert_eq!(decode_code(state), Some(0));
                        let previous = taken.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(previous, 0);
                        leases.push(buffer);
                    });
                })
            };
            let drainer = {
                let set = Arc::clone(&set);
                let drained = Arc::clone(&drained);
                thread::spawn(move || {
                    drained.store(set.drain(), Ordering::Relaxed);
                })
            };

            taker.join().unwrap();
            drainer.join().unwrap();
            assert_eq!(
                taken.load(Ordering::Relaxed) + drained.load(Ordering::Relaxed),
                1
            );

            // The observer may have conservatively repaired the low bit even
            // if drain won the leaf. Removing the manually installed code must
            // preserve that low state for ordinary cleanup.
            stripe
                .summary
                .fetch_and(AVAILABILITY_MASK, Ordering::Release);
            assert!(set.take().is_none());
            assert_eq!(stripe.summary.load(Ordering::Acquire), 0);
        });
    }

    #[test]
    fn summary_paired_group_reaches_partial_final_leaf() {
        loom::model(|| {
            let layout = Layout::from_size_align(64, 64).unwrap();
            let set = Arc::new(Freelist::new_inner(
                NZU32!(65),
                NZUsize!(1),
                layout,
                true,
                ConstructionOptions {
                    force_summaries: true,
                    max_groups: 1,
                },
            ));
            assert_eq!(set.stripes[0].group_count, 1);
            assert_eq!(set.stripes[0].single_groups, 0);

            let leases = Leases::new(Arc::clone(&set));
            let mut target = None;
            let mut entries = Vec::new();
            assert_eq!(set.take_batch(65, |buffer| entries.push(buffer)), 65);
            for buffer in entries {
                if buffer.slot() == 64 {
                    target = Some(buffer);
                } else {
                    leases.push(buffer);
                }
            }

            set.put(target.expect("partial final leaf slot"));
            let buffer = set.take().expect("paired group must reach its tail leaf");
            assert_eq!(buffer.slot(), 64);
            leases.push(buffer);
        });
    }

    #[test]
    fn summary_drain_races_put_without_touching_navigation() {
        loom::model(|| {
            let set = Arc::new(forced_summary_freelist(1));
            let buffer = set.try_create(false).expect("slot");
            let stripe = &set.stripes[0];
            let code = encode_code(0);
            let group = group_mask(0);
            stripe.summary.fetch_or(code, Ordering::Release);

            let drained = Arc::new(AtomicUsize::new(0));
            let writer = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put(buffer))
            };
            let drainer = {
                let set = Arc::clone(&set);
                let drained = Arc::clone(&drained);
                thread::spawn(move || {
                    drained.store(set.drain(), Ordering::Relaxed);
                })
            };

            writer.join().unwrap();
            drainer.join().unwrap();
            assert_eq!(stripe.summary.load(Ordering::Acquire), code | group);

            let total = drained.load(Ordering::Relaxed) + set.drain();
            assert_eq!(total, 1);
            assert_eq!(stripe.summary.load(Ordering::Acquire), code | group);

            stripe
                .summary
                .fetch_and(AVAILABILITY_MASK, Ordering::Release);
            assert!(set.take().is_none());
            assert_eq!(stripe.summary.load(Ordering::Acquire), 0);
        });
    }

    #[test]
    fn summary_cleanup_guard_restores_state_during_unwind() {
        loom::model(|| {
            let summary = AtomicU64::new(encode_code(0) | group_mask(1));
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = CleanupGuard::new(&summary, group_mask(0));
                panic!("injected cleanup failure");
            }));

            assert!(panic.is_err());
            assert_eq!(
                summary.load(Ordering::Acquire),
                group_mask(0) | group_mask(1)
            );
        });
    }

    #[test]
    fn creation_cursor_first_claim_installs_phase_for_followers() {
        loom::model(|| {
            let cursor = Arc::new(CreationCursor::new(0));
            let claims = Arc::new(Mutex::new(Vec::new()));
            let requested_phases = [0x1234, 0x5678];
            let mut creators = Vec::new();

            for requested in requested_phases {
                creators.push(thread::spawn({
                    let cursor = Arc::clone(&cursor);
                    let claims = Arc::clone(&claims);
                    move || {
                        let (adopted, ticket) = cursor
                            .claim(requested, 2)
                            .expect("both cursor claims must fit");
                        claims.lock().push((requested, adopted, ticket));
                    }
                }));
            }

            for creator in creators {
                creator.join().unwrap();
            }

            let mut claims = claims.lock();
            claims.sort_unstable_by_key(|claim| claim.2);
            assert_eq!(claims.len(), 2);
            assert_eq!(claims[0].2, 0);
            assert_eq!(claims[1].2, 1);
            assert_eq!(claims[0].1, claims[0].0);
            assert_eq!(claims[1].1, claims[0].1);
            assert!(requested_phases.contains(&claims[0].1));

            let state = cursor.state.load(Ordering::Relaxed);
            assert_eq!(decode_cursor_phase(state), claims[0].1);
            assert_eq!(decode_cursor_next(state), 2);
        });
    }

    // Each geometry gives a model a small bitmap layout: one or more active
    // bitmap words, with either one or multiple free bits per active word.
    // The names spell out that words-by-bits matrix.
    #[allow(clippy::enum_variant_names)]
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
                Self::MultiWordSingleBit => {
                    let layout = Layout::from_size_align(64, 64).unwrap();
                    Freelist::new(NZU32!(4), NZUsize!(4), layout, false)
                }
                Self::MultiWordMultiBit => {
                    let layout = Layout::from_size_align(64, 64).unwrap();
                    Freelist::new(NZU32!(4), NZUsize!(2), layout, false)
                }
            }
        }

        // Returns the slot ids that are active in this geometry. Models use
        // only the first id and the id set. The order is not significant.
        const fn slots(self) -> &'static [u32] {
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
        buffers: Mutex<Vec<PooledBuffer>>,
    }

    impl Leases {
        fn new(freelist: Arc<Freelist>) -> Arc<Self> {
            Arc::new(Self {
                freelist,
                buffers: Mutex::new(Vec::new()),
            })
        }

        fn reserve(freelist: Arc<Freelist>) -> (Arc<Self>, Vec<PooledBuffer>) {
            let entries = Self::entries(&freelist);
            (Self::new(freelist), entries)
        }

        fn entries(freelist: &Freelist) -> Vec<PooledBuffer> {
            let mut entries = Vec::new();
            while let Some(entry) = freelist.try_create(false) {
                entries.push(entry);
            }
            entries
        }

        fn push(&self, buffer: PooledBuffer) {
            self.buffers.lock().push(buffer);
        }

        fn push_expected(&self, seen: &AtomicUsize, expected: usize, buffer: PooledBuffer) {
            let slot = buffer.slot();
            let mask = 1usize << slot;
            assert_ne!(expected & mask, 0);
            let previous = seen.fetch_or(mask, Ordering::Relaxed);
            assert_eq!(previous & mask, 0);
            self.push(buffer);
        }
    }

    impl Drop for Leases {
        fn drop(&mut self) {
            for buffer in self.buffers.lock().drain(..) {
                self.freelist.put(buffer);
            }
        }
    }

    #[test]
    fn concurrent_creates_do_not_duplicate_slots() {
        // `created` admits the two creators, then relaxed stripe cursors choose
        // their slot ids. Parallelism 1 places both slots in one word and
        // models two creators advancing one cursor. Parallelism 2 gives each
        // slot its own stripe, so a creator that claims both permits must move
        // from its full home cursor to the remaining cursor.
        for parallelism in [1, 2] {
            loom::model(move || {
                let freelist = Arc::new(Freelist::new(
                    NZU32!(2),
                    NZUsize!(parallelism),
                    Layout::from_size_align(64, 64).unwrap(),
                    false,
                ));
                let seen = Arc::new(AtomicUsize::new(0));
                let expected = 0b11;
                let leases = Leases::new(freelist.clone());
                let mut handles = Vec::new();

                for _ in 0..2 {
                    handles.push(thread::spawn({
                        let freelist = freelist.clone();
                        let seen = seen.clone();
                        let leases = leases.clone();
                        move || {
                            while let Some(buffer) = freelist.try_create(false) {
                                leases.push_expected(&seen, expected, buffer);
                            }
                        }
                    }));
                }

                for handle in handles {
                    handle.join().unwrap();
                }

                assert_eq!(seen.load(Ordering::Relaxed), expected);
                assert_eq!(freelist.created.load(Ordering::Relaxed), 2);
            });
        }
    }

    #[test]
    fn put_publishes_before_take() {
        // `put` publishes the returned slot with a Release RMW. The taker
        // spins until it can clear that bit with an Acquire RMW, then rebuilds
        // a buffer handle from the same side-table slot. The stamp pins the
        // publication edge itself: the producer's pre-put write must be
        // visible and race-free to the claimant.
        model(&ALL_GEOMETRIES, |_, freelist| {
            let buffer = freelist.try_create(false).unwrap();
            let slot = buffer.slot();
            let leases = Leases::new(freelist.clone());
            let stamps = SlotStamps::new(4);

            let writer = thread::spawn({
                let freelist = freelist.clone();
                let stamps = stamps.clone();
                move || {
                    stamps.write(slot);
                    freelist.put(buffer)
                }
            });

            let reader = thread::spawn({
                let leases = leases.clone();
                move || loop {
                    if let Some(buffer) = freelist.take() {
                        assert_eq!(buffer.slot(), slot);
                        stamps.assert_visible(slot);
                        leases.push(buffer);
                        break;
                    }
                    thread::yield_now();
                }
            });

            writer.join().unwrap();
            reader.join().unwrap();

            // Keep the taken buffers checked out until the model is done:
            // Leases returns them to the freelist on drop.
            drop(leases);
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
            let buffer0 = entries.pop().unwrap();
            let buffer1 = entries.pop().unwrap();

            let first = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put(buffer0)
            });

            let second = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put(buffer1)
            });

            first.join().unwrap();
            second.join().unwrap();

            assert_eq!(
                freelist.take_batch(2, |buffer| {
                    leases.push_expected(&seen, expected, buffer)
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
                freelist.take_batch(4, |buffer| {
                    leases.push_expected(&seen, expected, buffer)
                }),
                4
            );
            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn put_and_take_compose_on_partially_free_word() {
        // One slot starts free, then a producer returns another slot while
        // `take` races on the same bitmap word. The producer's `fetch_or` must
        // compose with the consumer's `fetch_and`: clearing the existing bit
        // must not lose the newly published bit, and publishing the new bit
        // must not resurrect a claimed bit.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(2));
            let (leases, mut entries) = Leases::reserve(freelist.clone());
            let initial_entry = entries.pop().unwrap();
            let writer_entry = entries.pop().unwrap();
            assert!(entries.pop().is_none());
            freelist.put(initial_entry);

            let seen = Arc::new(AtomicUsize::new(0));
            let expected = 0b11;

            let writer = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put(writer_entry)
            });

            let taker = thread::spawn({
                let freelist = freelist.clone();
                let seen = seen.clone();
                let leases = leases.clone();
                move || {
                    let buffer = freelist.take().expect("slot 0 starts free");
                    leases.push_expected(&seen, expected, buffer);
                }
            });

            writer.join().unwrap();
            taker.join().unwrap();

            // The taker may run before slot 1 is published. After the writer
            // has joined, any slot not claimed during the race must still be
            // available exactly once.
            while let Some(buffer) = freelist.take() {
                leases.push_expected(&seen, expected, buffer);
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
            freelist.put(initial_entry);

            let seen = Arc::new(AtomicUsize::new(0));
            let expected = 0b11;

            let writer = thread::spawn({
                let freelist = freelist.clone();
                move || freelist.put(writer_entry)
            });

            let batch_taker = thread::spawn({
                let freelist = freelist.clone();
                let seen = seen.clone();
                let leases = leases.clone();
                move || {
                    let count = freelist.take_batch(2, |buffer| {
                        leases.push_expected(&seen, expected, buffer);
                    });
                    assert!((1..=2).contains(&count));
                }
            });

            writer.join().unwrap();
            batch_taker.join().unwrap();

            // If the batch taker ran before slot 1 was published, the slot must
            // still be visible after the writer completes.
            while let Some(buffer) = freelist.take() {
                leases.push_expected(&seen, expected, buffer);
            }

            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(freelist.drain(), 0);
        });
    }

    #[test]
    fn put_batch_and_drain_compose_on_partially_free_word() {
        // One slot starts free, then a batch producer stages two more slots and
        // publishes them with one `fetch_or`. A concurrent `drain` clears the
        // whole word with `swap(0)`. The two RMWs must compose: the drainer may
        // get only the initial slot or all three slots, but the slots it misses
        // must remain available after the writer completes.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(3));
            let mut entries = Leases::entries(&freelist);
            let writer_entry0 = entries.pop().unwrap();
            let writer_entry1 = entries.pop().unwrap();
            let initial_entry = entries.pop().unwrap();
            assert!(entries.pop().is_none());
            freelist.put(initial_entry);

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
            let buffer = freelist.try_create(false).unwrap();
            let created_slot = buffer.slot();
            freelist.put(buffer);

            let seen = Arc::new(AtomicUsize::new(0));
            let expected = 1usize << created_slot;
            let mut handles = Vec::new();
            let leases = Leases::new(freelist.clone());

            for _ in 0..2 {
                handles.push(thread::spawn({
                    let freelist = freelist.clone();
                    let seen = seen.clone();
                    let leases = leases.clone();
                    move || {
                        if let Some(buffer) = freelist.take() {
                            leases.push_expected(&seen, expected, buffer);
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
            freelist.put(entry);

            let transfers = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            for _ in 0..2 {
                handles.push(thread::spawn({
                    let freelist = freelist.clone();
                    let transfers = transfers.clone();
                    let leases = leases.clone();
                    move || loop {
                        if let Some(buffer) = freelist.take() {
                            let slot = buffer.slot();
                            assert_eq!(slot, 0);
                            let transfer = transfers.fetch_add(1, Ordering::Relaxed) + 1;
                            if transfer == 1 {
                                freelist.put(buffer);
                            } else {
                                leases.push(buffer);
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
                        if let Some(buffer) = freelist.take() {
                            leases.push_expected(&seen, expected, buffer);
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
                    let count = freelist.take_batch(slots.len(), |buffer| {
                        batch_callbacks.fetch_add(1, Ordering::Relaxed);
                        leases.push_expected(&seen, expected, buffer);
                    });
                    batch_count.store(count, Ordering::Relaxed);
                }
            });

            let single_taker = thread::spawn({
                let seen = seen.clone();
                let leases = leases.clone();
                move || {
                    if let Some(buffer) = freelist.take() {
                        leases.push_expected(&seen, expected, buffer);
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

            // Keep the taken buffers checked out until the model is done:
            // Leases returns them to the freelist on drop.
            drop(leases);
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
                        let count = freelist.take_batch(slots.len(), |buffer| {
                            leases.push_expected(&seen, expected, buffer);
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
                        let count = freelist.take_batch(2, |buffer| {
                            leases.push_expected(&seen, expected, buffer);
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
        // make returned slots visible, and Acquire `fetch_and` claims may
        // transfer one or more bits per word.
        //
        // The reader loops because loom may run it before the writer has
        // published anything. A zero-sized claim is just a retry, not an
        // observable failure.
        //
        // Per-slot stamps pin the batch publication edge: every staged slot's
        // pre-publish write must be visible and race-free to whichever
        // claimant ends up with that slot.
        model(&BATCH_GEOMETRIES, |geometry, freelist| {
            let seen = Arc::new(AtomicUsize::new(0));
            let slots = geometry.slots();
            let expected = geometry.slot_mask();
            let (leases, entries) = Leases::reserve(freelist.clone());
            let stamps = SlotStamps::new(4);

            let writer = thread::spawn({
                let freelist = freelist.clone();
                let stamps = stamps.clone();
                move || {
                    for entry in &entries {
                        stamps.write(entry.slot());
                    }
                    freelist.put_batch(entries)
                }
            });

            let reader = thread::spawn({
                let seen = seen.clone();
                let leases = leases.clone();
                move || {
                    while seen.load(Ordering::Relaxed) != expected {
                        let claimed = freelist.take_batch(slots.len(), |buffer| {
                            stamps.assert_visible(buffer.slot());
                            leases.push_expected(&seen, expected, buffer);
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

            // Keep the taken buffers checked out until the model is done:
            // Leases returns them to the freelist on drop.
            drop(leases);
        });
    }

    #[test]
    fn put_publishes_to_drain() {
        // `drain` uses an Acquire whole-word swap. Run it concurrently with
        // publication so this model checks the put-side Release edge rather
        // than relying on thread-spawn visibility from pre-populated state.
        //
        // If the swap does not compose with the successful put, the model can
        // lose or duplicate the returned slot.
        model(&ALL_GEOMETRIES, |_, freelist| {
            let drained = Arc::new(AtomicUsize::new(0));
            let buffer = freelist.try_create(false).unwrap();
            let slot = buffer.slot();
            let stamps = SlotStamps::new(4);

            let writer = thread::spawn({
                let freelist = freelist.clone();
                let stamps = stamps.clone();
                move || {
                    stamps.write(slot);
                    freelist.put(buffer)
                }
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
                            // The Acquire swap must make the producer's
                            // pre-put write visible to the draining thread.
                            stamps.assert_visible(slot);
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
        // A batch publish stages multiple returned slots before publishing the
        // touched bitmap word masks. The drainer loops until its Acquire swaps
        // have observed every publication and dropped every returned buffer.
        //
        // This is the drain analogue of `put_batch_publishes_to_take_batch`:
        // each whole-word swap must claim all slots represented by the returned
        // word exactly once before they are dropped.
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
                    for buffer in entries {
                        freelist.put(buffer);
                    }
                }
            });

            let reader = thread::spawn({
                let freelist = freelist.clone();
                let seen = seen.clone();
                let leases = leases.clone();
                move || {
                    while seen.load(Ordering::Relaxed) != expected {
                        if let Some(buffer) = freelist.take() {
                            leases.push_expected(&seen, expected, buffer);
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

            // Keep the taken buffers checked out until the model is done:
            // Leases returns them to the freelist on drop.
            drop(leases);
        });
    }

    #[test]
    fn drain_and_take_do_not_duplicate_or_lose_slots() {
        // `drain` clears a whole word with `swap(0)` while `take` clears one
        // bit with `fetch_and`. Racing them should transfer ownership of each
        // globally free buffer exactly once and leave no free bits behind.
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
                    if let Some(buffer) = freelist.take() {
                        leases.push_expected(&taken, expected_mask, buffer);
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

            // Keep the taken buffers checked out until the model is done:
            // Leases returns them to the freelist on drop.
            drop(leases);
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
                    let count = freelist.take_batch(expected, |buffer| {
                        leases.push_expected(&taken_slots, expected_mask, buffer);
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

            // Keep the taken buffers checked out until the model is done:
            // Leases returns them to the freelist on drop.
            drop(leases);
        });
    }
}
