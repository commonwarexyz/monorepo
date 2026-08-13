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
//! The buffer pool keeps this requirement by storing a live size-class lease in
//! every pooled buffer outside the freelist, including buffers held in a
//! thread-local cache. Those leases keep the owning size class, and therefore
//! this freelist, alive until the buffer returns here.
//!
//! This is intentionally narrower than a general multi-producer,
//! multi-consumer queue:
//!
//! - Capacity is fixed when the size class is created.
//! - Callers only need to take any free slot, not preserve order.
//! - Slot ownership is managed by the buffer pool.
//! - Refill and spill paths naturally move buffers in batches.
//!
//! The freelist divides its fixed capacity among a power-of-two number of
//! cache-isolated stripes. Slot ids are interleaved across those stripes, and
//! threads begin at stable home stripes before stealing from the others. Each
//! stripe stores packed free words and stable owner records for its valid local
//! slots. A set free bit is the sole ownership authority. Larger layouts add an
//! advisory summary word per stripe to bound settled-empty searches, while
//! small layouts scan free words directly. A separate monotonic cursor
//! for each stripe assigns uncreated slots in the same probe order used for
//! reuse.
//!
//! # Ownership model
//!
//! Every potential slot has a stable global id, one [`PooledOwner`] side-table
//! entry, and one authoritative free bit. The side-table entry lives for
//! the entire size-class lifetime and stores the data pointer, capacity,
//! routing fields, refcount, and any live size-class lease. A global admission
//! counter and one monotonic cursor per stripe assign each slot to at most one
//! lazy creation.
//!
//! For a created, live buffer, the free bit determines whether the freelist or
//! an outside owner holds the allocation:
//!
//! ```text
//! +------------------------+                           +-------------------+
//! | checked out or cached  | <--- take: Acquire RMW -- | globally parked  |
//! | free bit = 0           | --- put: Release RMW ---> | free bit = 1      |
//! +------------------------+                           +-------------------+
//!                                                            |
//!                                                            +-- Release summary RMW
//!                                                                when enabled
//! ```
//!
//! Returning a buffer removes its live lease, Release-publishes its free bit
//! with a word RMW, and, when summaries are enabled, publishes the corresponding
//! advisory group. The pool releases the lease's size-class reference only
//! after publication is complete. Taking clears a set free bit with an Acquire
//! RMW, rebuilds a [`PooledBuffer`] from the side-table entry, and lets the pool
//! install a new lease before exposing it to a caller or thread-local cache.
//!
//! A set free bit therefore means the freelist exclusively owns that buffer. A
//! clear bit does not by itself promise a live allocation. It can also mean
//! that the slot has not been created yet or that drain permanently deallocated
//! it. Monotonic creation state distinguishes the first case, and drain never
//! reopens a creation ticket for the second.
//!
//! The owner records are allocated and metadata-initialized before the
//! freelist is shared. Lazy creation initializes only the selected record's
//! data allocation. The owner slices never move afterward, so handles may
//! safely retain pointers into them while the containing size class remains
//! alive.
//!
//! # Stripes and physical layout
//!
//! Capacity is interleaved across a power-of-two number of cache-isolated
//! stripes. Expected parallelism supplies the normal stripe target. Capacity
//! may raise it so that, with the current `u32` slot ids, no stripe contains
//! more than `2^24` slots. The count is at most 4096 and never exceeds the
//! freelist capacity.
//!
//! For capacity `C` and configured parallelism `P`, construction chooses:
//!
//! ```text
//! parallelism stripes = min(next_power_of_two(P), 4096)
//! capacity stripes    = min(next_power_of_two(ceil(C / 2^24)), 4096)
//! capacity ceiling    = greatest power of two at most C
//!
//! S = min(max(parallelism stripes, capacity stripes), capacity ceiling)
//! ```
//!
//! Checked power-of-two overflow saturates at 4096 before the capacity ceiling
//! is applied.
//!
//! ```text
//! Freelist
//! +-- layout and fixed capacity
//! +-- created                    cache-padded global admission counter
//! +-- stripes[S]
//! |   +-- Stripe 0
//! |   |   +-- summary            [ cleaning code: 6 | availability: 58 ]
//! |   |   +-- free words          packed, cache-aligned blocks of AtomicU64
//! |   |   +-- slots              stable stripe-local PooledOwner records
//! |   |   +-- valid extent        slot, word, and summary-group bounds
//! |   +-- ...
//! |   +-- Stripe S-1
//! +-- creation_cursors[S]        separate cache-padded cursor array
//! ```
//!
//! Stripe routing and the base summary-group width are common to all stripes.
//! Capacity need not divide evenly, so stripe capacities differ by at most one
//! slot and each stripe records its exact valid word and group extent. Its
//! group count and tail pairing are derived from that extent, so no group
//! addresses physical padding.
//!
//! Separating the creation cursors and global admission counter prevents lazy
//! growth from invalidating the summary cache lines read by normal takes. Free
//! words are packed inside aligned [`FreeWordBlock`]s. Padding every individual
//! word would make metadata and empty scans scale poorly, while an ordinary
//! boxed atomic slice would not isolate separately allocated stripes.
//!
//! Consecutive slot ids are not packed into one stripe. Low slot-id bits choose
//! the stripe and high bits choose the stripe-local slot. With power-of-two
//! stripe count `S`, the mapping is only shifts and masks:
//!
//! ```text
//! stripe mask  = S - 1
//! stripe shift = log2(S)
//! stripe       = slot & stripe mask
//! local        = slot >> stripe shift
//! free word    = local >> 6
//! free bit     = local & 63
//!
//! slot      = (local << stripe shift) | stripe
//! ```
//!
//! For an eight-stripe freelist, slots are arranged like this:
//!
//! ```text
//!             stripe 0  stripe 1  stripe 2  stripe 3  stripe 4  stripe 5  stripe 6  stripe 7
//! word 0 bit 0: slot 0    slot 1    slot 2    slot 3    slot 4    slot 5    slot 6    slot 7
//! word 0 bit 1: slot 8    slot 9    slot 10   slot 11   slot 12   slot 13   slot 14   slot 15
//! word 0 bit 2: slot 16   slot 17   slot 18   slot 19   slot 20   slot 21   slot 22   slot 23
//! ...
//! ```
//!
//! This gives concurrent threads independent cache-isolated contention domains
//! without changing the stable slot ids handed back to the pool. Within one
//! stripe, consecutive local slots share packed free words and adjacent stable
//! owner records, which keeps a successful claim and owner lookup local.
//!
//! Construction proves that every valid inverse mapping is below capacity and
//! fits in `u32`. Physical padding words and unused bits in a final free word
//! are never part of slot arithmetic.
//!
//! # Probe affinity
//!
//! Lazy creation starts from the same stripe, group, word, and bit phases as
//! reuse. The global `created` counter grants capacity admission but does not
//! choose a slot id. If that counter's value directly selected the slot, a
//! worker could create buffers in a stripe far from its home and then begin
//! later reuse somewhere else. Stripe-local creation cursors instead enumerate
//! tickets group-major from the winning probe's first position, exhausting one
//! group before advancing to the next.
//!
//! Each thread gets a stable probe id. Low bits of the raw id choose its home
//! stripe, while a mixer over the complete id supplies independent group, word,
//! and bit phases. The first `S` long-lived workers therefore start on distinct
//! stripes. Workers that collide on a home stripe are mixed to spread their
//! starting positions inside it:
//!
//! ```text
//! stripe count = 8
//!
//! raw thread id:  0  1  2  3  4  5  6  7 |  8  9 10 11 12 13 14 15
//! home stripe:    0  1  2  3  4  5  6  7 |  0  1  2  3  4  5  6  7
//! local phases:   <--------- mix(raw thread id) into group, word, bit -------->
//!
//! home_stripe = raw_thread_id & (S - 1)
//! ```
//!
//! These are stable phases, not shared mutable cursors. A take selects the
//! first advertised group at or after its group phase, starts that group at its
//! reduced word phase, and rotates bit selection from its bit phase. Stealing
//! into another stripe applies the same raw phases to that stripe's geometry.
//! The first creator to initialize a stripe cursor stores its complete phase so
//! later creation tickets preserve the same locality even if they were admitted
//! by colliding threads.
//!
//! # Hot paths
//!
//! The hot paths are fast for a few concrete reasons:
//!
//! - [`Freelist::try_create`] starts from the same stable per-thread home stripe
//!   and phases as [`Freelist::take`], so lazily created buffers tend to park
//!   where their creating thread will look first when they later return.
//! - [`Freelist::put`] is one free-word `fetch_or` in direct mode. Summarized
//!   mode adds one stripe-local summary `fetch_or` to bound later empty searches.
//! - A take starts at a stable per-thread home stripe, so long-lived threads
//!   tend to target different contention domains.
//! - Group, word, and bit phases keep threads sharing a stripe from converging
//!   on the same first free word and slot.
//! - A take claims bits with `fetch_and` instead of a compare-and-swap loop.
//!   Two threads removing different bits from the same free word can both
//!   succeed without either restarting from scratch.
//! - A settled-empty summarized take reads one compact state word per stripe
//!   instead of scanning every packed free word.
//! - [`Freelist::put_batch`] coalesces returned slots per free word and
//!   publishes all touched groups with one summary RMW per stripe.
//! - [`Freelist::take_batch`] claims several bits from one free word with one
//!   atomic operation, matching refill into a thread-local cache.
//!
//! # Advisory group geometry
//!
//! Let `W` be the largest logical free-word count in any stripe. Every stripe
//! uses the same power-of-two base chunk width:
//!
//! ```text
//! K = next_power_of_two(ceil(W / 64))
//! ```
//!
//! This produces at most 64 base chunks per stripe. A summary has room for 58
//! availability groups, so only excess tail chunks are paired. A 64-chunk
//! stripe, the widest possible geometry, is mapped as follows:
//!
//! ```text
//! base chunks:  0   1   ...  50  51  52  53  54  55  ...  62  63
//! groups:      [0] [1]  ... [50][51][  52 ][  53 ]  ... [  57 ]
//!                                  pair    pair           pair
//! ```
//!
//! Smaller geometries with at most 58 chunks use one group per chunk. Pairing
//! only the tail keeps 52 groups at the base width in the largest geometry.
//! Since `K <= 4096`, one selected group covers at most `2K = 8192` free words.
//! The group mapping changes search granularity only. Free bits remain exact.
//!
//! # Direct and summarized modes
//!
//! The freelist selects one traversal mode for its complete lifetime:
//!
//! - On every supported target, automatic policy directly scans free words
//!   when the whole freelist occupies at most 32 physical free-word blocks.
//! - Larger layouts use summary navigation.
//!
//! The cutoff is an aggregate allocation and scan budget, not a per-stripe
//! width test. The block-count threshold is the same on every target, while
//! the number of packed words in a block is derived from the target's
//! production cache-padded atomic representation. In direct mode the inline
//! summary words remain zero and unused. A put's free-word RMW is then its
//! complete publication. A direct-mode take scans free words from its
//! phase-selected start and advances through wrapped stripes until it fills
//! the request or exhausts the pass.
//!
//! In summarized mode each stripe's inline [`AtomicU64`] has this fixed layout:
//!
//! ```text
//! 63                 58 57                                      0
//! +--------------------+-----------------------------------------+
//! | cleaning code (6)  | availability bits A_57 ... A_1 A_0 (58)|
//! +--------------------+-----------------------------------------+
//!
//! code = 0      no group is being cleaned
//! code = g + 1  group g is being validated
//! ```
//!
//! Six code bits represent 59 states, idle plus one of 58 groups. An
//! availability bit means its group may contain a free slot. It may remain set
//! after the final free bit is claimed, so false positives are expected and are
//! cleaned lazily. The high code is exact. At most one cleaner owns a stripe,
//! and a nonzero code names the precise group whose low bit was temporarily
//! replaced.
//!
//! The key visibility invariant is stronger than a generic hint. After a
//! summarized put to group `g` completes, every later value in that summary's
//! modification order has either `A_g = 1` or `code = g + 1` until the
//! published free bit is claimed. Consequently, once operations quiesce, a
//! zero summary implies that all authoritative free words in that stripe are
//! zero.
//! Every summary mutation after sharing is a masked RMW. Only constructor and
//! prefill initialization use stores.
//!
//! The complete synchronization table is:
//!
//! | Operation | Ordering |
//! | --- | --- |
//! | Single or batch free-bit publication | word `fetch_or(Release)` |
//! | Summary publication or repair | masked `fetch_or(Release)` |
//! | Summary and ordinary free-word loads | `load(Acquire)` |
//! | Free-bit ownership claim | word `fetch_and(Acquire)` |
//! | Cleanup ownership CAS | `AcqRel` success, `Acquire` failure |
//! | Cleanup code removal | masked `fetch_and(Release)` |
//! | Drain ownership claim | `swap(0, Acquire)` |
//! | Creation admission and cursor reservation | `Relaxed` |
//!
//! # Return publication
//!
//! A single summarized [`Freelist::put`] publishes in this order:
//!
//! ```text
//! free_word.fetch_or(slot_mask, Release)
//!            |
//!            v
//! summary.fetch_or(group_mask, Release)    always, even if A_g was already 1
//!            |
//!            v
//! assert that the free bit was previously clear
//! ```
//!
//! The summary operation is an unconditional masked RMW. It cannot be replaced
//! by a store, by transition-only publication, or by a load followed by a
//! conditional RMW. The RMW preserves sibling availability and any active
//! cleaning code. Placing the overlap assertion last also ensures that an
//! invalid double return cannot unwind between free-word publication and
//! summary notification.
//!
//! There is a short visibility window if a put is paused between the two RMWs.
//! That put has not completed, and any later completed put to the same group
//! helps publish both free bits. Direct mode has no second phase and therefore
//! no such window.
//!
//! # Taking and bounded traversal
//!
//! Each thread receives a stable probe id. Its raw id chooses a home stripe,
//! while a mixed form supplies independent group, word, and bit phases:
//!
//! ```text
//! probe phase
//! 38                         12 11             6 5              0
//! +----------------------------+----------------+----------------+
//! | raw word phase (27 bits)   | bit phase (6)  | group phase (6)|
//! +----------------------------+----------------+----------------+
//! ```
//!
//! A take visits stripes in wrapped order from its home and stops on success.
//! An unsuccessful take visits every stripe exactly once. In summarized mode
//! it Acquire-loads one pass-local state snapshot per stripe. Low availability
//! candidates are selected cyclically from the group phase. A nonzero code
//! contributes its one exact named group. Later control loads may contribute
//! another observed code, but they never add fresh low-bit candidates from
//! outside the original snapshot. Each selected group is processed at most
//! once.
//!
//! Within a group, words are visited cyclically from the reduced raw word
//! phase. Within a word, bits are selected cyclically from the bit phase. An
//! Acquire `fetch_and` claims one bit for [`Freelist::take`] or a bounded set
//! for [`Freelist::take_batch`]. The word returned by the RMW may reveal bits
//! published after the candidate load. Those bits are added to the local
//! candidate set, but an `attempted` mask prevents any physical bit from being
//! tried twice during one word scan. This preserves useful finite helping while
//! bounding a word scan to at most 64 claim attempts under concurrent handoff.
//!
//! A failed take is therefore one bounded, opportunistic pass. A concurrent
//! return behind the pass can be deferred until the next call, so an empty
//! result is not a linearizable global-empty snapshot. The protocol does
//! provide starts-after visibility: if a completed put happens before a take
//! begins with a happens-before edge, and its free bit remains set throughout
//! that take, the take cannot report empty.
//!
//! # Exact stale-summary cleanup
//!
//! A taker that scans an advertised group without claiming a buffer may try to
//! clean its stale bit. Clearing the bit and validating later would create an
//! invisible interval, so cleanup atomically replaces the low bit with the
//! exact high code:
//!
//! ```text
//!       A_g = 1, code = 0
//!                |
//!                | compare_exchange(AcqRel), one attempt
//!                v
//!       A_g = 0, code = g + 1
//!                |
//!                | Acquire-load free words until nonzero or exhausted
//!                v
//!       +-------------------+----------------------+
//!       | first nonzero     | all free words zero  |
//!       | repair A_g        | keep A_g clear       |
//!       +-------------------+----------------------+
//!                |                    |
//!                +---------+----------+
//!                          v
//!       clear only the code with a Release fetch_and
//! ```
//!
//! Cleanup makes at most one strong CAS attempt for a selected group. A foreign
//! code is never overwritten. A taker that observes one scans the named group
//! instead of waiting. The code owner stops validation at its first nonzero
//! free word, Release-repairs `A_g` once, removes its code, and only then claims
//! that word and scans the unvisited suffix. An observer Release-repairs `A_g`
//! before every claim from a nonzero candidate observation while the foreign
//! code remains installed. It never clears the code. Both paths repair before
//! rebuilding a buffer or invoking a callback.
//!
//! After the cleanup CAS succeeds, the owner performs only immutable
//! construction-validated range arithmetic and atomic operations until it
//! removes the code. It does not allocate, reconstruct a buffer, or invoke
//! caller code inside that interval. The code is removed before any ownership
//! claim or callback, so cleanup needs no unwind guard.
//!
//! The publication and cleanup orders close every completed-put race:
//!
//! - If the put's summary RMW precedes the cleanup CAS, the CAS acquires that
//!   Release publication through the summary word's modification order and
//!   release sequence. Validation therefore cannot miss the earlier free-bit
//!   publication.
//! - If the put's summary RMW follows the cleanup CAS, it restores `A_g`, and
//!   the masked code removal preserves that bit.
//! - While validation is active, the code directs every observer to the exact
//!   group whose low bit is absent.
//!
//! A stalled cleaner can delay convergence of unrelated stale positives in the
//! same stripe because there is one code per stripe. It cannot hide a completed
//! free bit. Other takers continue to scan advertised groups and the exact
//! coded group without waiting.
//!
//! # Batch return
//!
//! [`Freelist::put_batch`] stages the complete input and validates every
//! in-batch duplicate before its first atomic publication. This is required for
//! exact duplicate rejection. Segmenting a large input could let a racing taker
//! remove an earlier duplicate before a later segment republishes it, defeating
//! overlap detection.
//!
//! Two staging layouts keep the common cases allocation-free:
//!
//! - When `stripe_count * maximum_logical_words <= 128`, a dense stack array
//!   accumulates one mask per logical free word.
//! - Larger free-word geometries collect touched records in a 128-record inline
//!   stage, spill to a `Vec` only when necessary, then sort and coalesce by
//!   stripe and free word.
//!
//! After duplicate validation, publication is stripe-major:
//!
//! ```text
//! for each touched stripe
//!     Release-OR every coalesced free-word mask
//!     Release-OR all touched group bits once when summaries are enabled
//!     assert that no published free bit overlapped an already-free bit
//! ```
//!
//! All free-word references, stripe indexes, and masks are resolved before the
//! atomic section. Each stripe's summary reference is resolved before that
//! stripe's first free-word RMW. No allocation, indexing, or callback occurs
//! between that RMW and the summary RMW. If the overlap assertion panics, prior
//! stripes are complete and the current stripe's notification is already
//! complete. The pool retains every size-class lease until publication for all
//! stripes has finished, so the freelist cannot be destroyed between those
//! accesses.
//!
//! # Lazy creation and prefill
//!
//! `created` is a relaxed, monotonic capacity-admission counter. It is not a
//! free count and ordinary reuse never changes it. After admission, creation
//! visits stripe cursors in the same wrapped order as a take. Each cursor packs
//! the first successful creator's complete probe phase with a next-ticket
//! field:
//!
//! ```text
//! 63                         25 24                              0
//! +----------------------------+--------------------------------+
//! | probe phase (39 bits)      | next ticket (25 bits)          |
//! +----------------------------+--------------------------------+
//!
//! state = 0  uninitialized cursor
//! ```
//!
//! The first claimant installs its phase, stores `next = 1`, and receives
//! ticket zero. Later claimants retain that stored phase while incrementing the
//! ticket. Constructor bounds of at most `2^24` slots per stripe keep the
//! fields disjoint.
//!
//! Tickets are unranked in group-major order. Creation starts at the same
//! phase-selected group, word, and bit as a hypothetical all-free take, exhausts
//! that group, then advances cyclically. In direct mode the whole stripe is one
//! creation group. Preserving the unreduced 27-bit word phase is important
//! because singleton and paired groups have different widths.
//!
//! All fallible preparation occurs before global admission. Eager owner
//! initialization and constructor-checked routing make the path after cursor
//! reservation infallible in a surviving process. Allocation failure uses the
//! allocator's aborting path rather than returning after consuming a permit.
//! Lazy creation honors the caller's `zeroed` request by choosing `alloc_zeroed`
//! or ordinary `alloc`. A reused buffer is already initialized storage but may
//! contain old bytes. The pool zeroes the requested readable range after taking
//! such a buffer for a zeroed allocation request.
//!
//! Prefill performs final initialization under exclusive construction. It
//! analytically constructs the valid free-word masks, low summary bits, full
//! cursors, and capacity-valued `created` counter, then initializes every data
//! allocation with ordinary non-zeroed allocation before the freelist is
//! shared. This construction-only order is safe because no take can observe a
//! free bit yet. Invalid free and summary bits remain zero.
//!
//! # Drain, drop, and safety
//!
//! [`Freelist::drain`] ignores summaries and uses an Acquire `swap(0)` on every
//! authoritative logical free word. A put ordered before a swap is drained. A
//! put ordered after it remains in the free word and completes its normal
//! publication. Drain deliberately does not clear summary words because a
//! later summary store could erase that racing publication. Continuing to use
//! a drained freelist is ownership-correct, although stale positives may make
//! the next take perform a full cleanup episode. Drain does not decrement
//! `created` or rewind a creation cursor, so every drained slot remains retired.
//!
//! The [`Drop`] implementation drains all globally parked buffers before the
//! stable owner storage is released. Buffers outside the freelist keep their
//! size class and this storage alive through the pool's lease protocol.
//!
//! The shared free-word and summary operations are lock-free, but this is not a
//! standalone general-purpose container. It relies on the buffer pool's
//! ownership discipline. A live slot is checked out in pooled backing state,
//! parked in one thread-local cache, or globally parked here. An uncreated or
//! drained slot has no live allocation. Only non-freelist ownership paths may
//! mutate a live slot while its free bit is clear.
//!
//! The manual [`Send`] and [`Sync`] implementations rely on two invariants:
//!
//! - A `PooledOwner` is mutated only while its free bit is clear and one caller
//!   or one creation cursor exclusively owns the slot.
//! - Release free-bit publication and Acquire free-bit claim synchronize every
//!   reuse handoff before the new owner reads or mutates the stable entry.
//!
//! Summaries never grant ownership and drain never trusts them. Keeping those
//! responsibilities separate is what allows hints to be stale without making
//! buffer ownership approximate.
//!
//! # Verification strategy
//!
//! The Loom suite separates broad ownership coverage from targeted summary
//! models so the additional summary atomics do not make every geometry matrix
//! intractable.
//!
//! Broad small-geometry models cover Release and Acquire publication, same-word
//! claim composition, wrapped cross-stripe scans, creation uniqueness, batch
//! claims, and drain races. Targeted forced-summary models cover delayed and
//! helped publication, competing cleaners, owner and observer repair ordering,
//! batch publication and overlap panic, stale state snapshots, tail pairing,
//! and concurrent drain. Pool and owner models separately cover the size-class
//! lease lifetime and refcount handoff that keep the stable owner storage alive
//! around these operations.

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

/// Number of slots represented by one authoritative free word.
const SLOT_WORD_BITS: usize = u64::BITS as usize;
/// Shift that maps a stripe-local slot index to its logical free word.
const SLOT_WORD_SHIFT: u32 = SLOT_WORD_BITS.trailing_zeros();
/// Maximum power-of-two stripe count for one freelist.
const MAX_FREELIST_STRIPES: usize = 4096;
/// Maximum slots assigned to one stripe before capacity requires more stripes.
const TARGET_MAX_SLOTS_PER_STRIPE: usize = 1 << 24;
/// Low summary bits reserved for advisory group availability.
const AVAILABILITY_BITS: usize = 58;
/// Bit position where the exact summary cleaning code begins.
const CODE_SHIFT: u32 = AVAILABILITY_BITS as u32;
/// Mask for all advisory availability bits in a summary word.
const AVAILABILITY_MASK: u64 = (1u64 << CODE_SHIFT) - 1;
/// Mask for the exact cleaning code in a summary word.
const CODE_MASK: u64 = !AVAILABILITY_MASK;
/// Width of the next-ticket field in a packed creation cursor.
const CURSOR_NEXT_BITS: u32 = 25;
/// Mask for the next-ticket field in a packed creation cursor.
const CURSOR_NEXT_MASK: u64 = (1u64 << CURSOR_NEXT_BITS) - 1;
/// Width of the group, bit, and word phases retained by a creation cursor.
const PROBE_PHASE_BITS: u32 = 39;
/// Mask for the complete packed probe phase.
const PROBE_PHASE_MASK: u64 = (1u64 << PROBE_PHASE_BITS) - 1;
/// Width of the unreduced word phase supplied by the probe mixer.
const WORD_PHASE_BITS: u32 = 27;
/// Mask for the unreduced word phase.
const WORD_PHASE_MASK: u64 = (1u64 << WORD_PHASE_BITS) - 1;
/// Maximum dense free-word mask table staged on the stack by `put_batch`.
const INLINE_FREE_WORD_MASKS: usize = 128;
/// Number of sparse put records retained inline before spilling to the heap.
const INLINE_PUT_RECORDS: usize = 128;
/// Aggregate physical free-word block cutoff for direct scanning.
const MAX_DIRECT_FREE_WORD_BLOCKS: usize = 32;

/// Production cache-padded atomic footprint used to size packed blocks.
///
/// Loom atomics deliberately have a different size. Deriving this value from
/// the production atomic keeps Loom's logical geometry equal to production.
const CACHE_PADDING_BYTES: usize = size_of::<CachePadded<std::sync::atomic::AtomicU64>>();
/// Number of packed atomic free words stored in one cache-padded block.
const FREE_WORDS_PER_BLOCK: usize = CACHE_PADDING_BYTES / size_of::<std::sync::atomic::AtomicU64>();

/// Cache-isolated storage block containing packed authoritative free words.
type FreeWordBlock = CachePadded<[AtomicU64; FREE_WORDS_PER_BLOCK]>;

// Block offsets use a mask, so the derived width must be a power of two.
const _: () = assert!(FREE_WORDS_PER_BLOCK.is_power_of_two());

#[cfg(not(feature = "loom"))]
// Native blocks must occupy exactly one production padding quantum. Loom uses
// different atomic storage and therefore checks only the logical block width.
const _: () = {
    assert!(size_of::<FreeWordBlock>() == CACHE_PADDING_BYTES);
    assert!(
        std::mem::align_of::<FreeWordBlock>() == std::mem::align_of::<CachePadded<AtomicU64>>()
    );
};

/// Validated allocation and navigation geometry for one freelist.
///
/// Construction computes this compact proof object before allocating any
/// capacity-sized owner or free-word storage.
#[derive(Clone, Copy)]
struct Geometry {
    /// Total number of stable global slots.
    capacity: usize,
    /// Power-of-two count of cache-isolated stripes.
    stripe_count: usize,
    /// Shift between global slot ids and stripe-local slot indices.
    stripe_shift: u32,
    /// Largest logical free-word count among all stripes.
    max_logical_words: usize,
    /// Common power-of-two width of one unpaired summary chunk.
    base_chunk_words: usize,
    /// Aggregate physical free-word blocks across every stripe.
    total_free_word_blocks: usize,
}

impl Geometry {
    /// Computes and validates geometry for `capacity` and expected parallelism.
    fn new(capacity: usize, parallelism: usize) -> Self {
        // Parallelism chooses the normal contention-domain count. Capacity may
        // raise it so every stripe remains encodable by the cursor ticket.
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
        let max_stripe_capacity = Self::stripe_capacity_for(capacity, stripe_shift, 0);
        let max_logical_words = max_stripe_capacity.div_ceil(SLOT_WORD_BITS);
        let base_chunk_words = max_logical_words
            .div_ceil(64)
            .checked_next_power_of_two()
            .expect("base chunk width must be representable");
        let mut total_free_word_blocks = 0usize;

        // The traversal policy is based on the aggregate physical scan budget,
        // including partially populated final blocks in each stripe.
        for stripe in 0..stripe_count {
            let stripe_capacity = Self::stripe_capacity_for(capacity, stripe_shift, stripe);
            let logical_words = stripe_capacity.div_ceil(SLOT_WORD_BITS);
            total_free_word_blocks = total_free_word_blocks
                .checked_add(logical_words.div_ceil(FREE_WORDS_PER_BLOCK))
                .expect("free-word block count must be representable");
        }

        let geometry = Self {
            capacity,
            stripe_count,
            stripe_shift,
            max_logical_words,
            base_chunk_words,
            total_free_word_blocks,
        };
        geometry.validate();
        geometry
    }

    /// Computes one stripe's exact capacity under interleaved slot mapping.
    #[inline(always)]
    const fn stripe_capacity_for(capacity: usize, stripe_shift: u32, stripe: usize) -> usize {
        ((capacity - 1 - stripe) >> stripe_shift) + 1
    }

    /// Returns one stripe's exact capacity in this geometry.
    #[inline(always)]
    const fn stripe_capacity(&self, stripe: usize) -> usize {
        Self::stripe_capacity_for(self.capacity, self.stripe_shift, stripe)
    }

    /// Maps a stripe-local slot index back to its stable global slot id.
    #[inline(always)]
    const fn slot(&self, stripe: usize, local: usize) -> usize {
        (local << self.stripe_shift) | stripe
    }

    /// Proves the geometry bounds and complete interleaved capacity mapping.
    fn validate(&self) {
        assert!(self.stripe_count.is_power_of_two());
        assert!(self.stripe_count <= self.capacity.min(MAX_FREELIST_STRIPES));
        assert!(self.max_logical_words <= 1 << 18);
        assert!(self.base_chunk_words <= 1 << 12);
        assert!(self.total_free_word_blocks > 0);

        // Checking each final local slot proves that every inverse mapping is
        // below capacity and representable by the public u32 slot id.
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

/// One cache-isolated contention and navigation domain.
struct Stripe {
    /// Advisory 58+6 availability and cleaning state.
    summary: AtomicU64,
    /// Packed cache-padded blocks containing authoritative free words.
    free_word_blocks: Box<[FreeWordBlock]>,
    /// Stable owner records for every valid stripe-local slot.
    slots: Box<[CachePadded<UnsafeCell<PooledOwner>>]>,
    /// Number of valid stripe-local slots.
    capacity: usize,
    /// Number of logical free words, excluding physical block padding.
    logical_words: usize,
    /// Number of valid advisory summary groups.
    group_count: u32,
    /// Leading groups that each map to one base chunk before tail pairing.
    single_groups: u32,
}

impl Stripe {
    /// Returns one authoritative free word from packed block storage.
    #[inline(always)]
    fn free_word(&self, logical_word: usize) -> &AtomicU64 {
        let block = logical_word / FREE_WORDS_PER_BLOCK;
        // The compile-time power-of-two proof makes masking equivalent to the
        // remainder while keeping this lookup cheap on the hot path.
        let offset = logical_word & (FREE_WORDS_PER_BLOCK - 1);
        &self.free_word_blocks[block][offset]
    }

    /// Returns the valid slot-bit mask for one logical free word.
    #[inline(always)]
    fn valid_free_word_mask(&self, logical_word: usize) -> u64 {
        // A partial final word excludes physical padding from candidate scans.
        let remaining = self.capacity - logical_word * SLOT_WORD_BITS;
        low_bits(remaining.min(SLOT_WORD_BITS))
    }
}

/// Packed monotonic creation state for one stripe.
struct CreationCursor {
    /// First creator's probe phase and the next unassigned local ticket.
    state: AtomicU64,
}

impl CreationCursor {
    /// Initializes a cursor from an already encoded state.
    #[inline(always)]
    #[allow(clippy::missing_const_for_fn)]
    fn new(state: u64) -> Self {
        Self {
            state: AtomicU64::new(state),
        }
    }

    /// Reserves the next ticket while retaining the first claimant's phase.
    ///
    /// Returns the retained phase and claimed zero-based ticket, or `None` when
    /// every ticket below `capacity` has already been assigned.
    #[inline(always)]
    fn claim(&self, probe_phase: u64, capacity: usize) -> Option<(u64, usize)> {
        // Creation state does not publish a buffer. Relaxed ordering is enough
        // for the atomic ticket assignment and one-time phase installation.
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

/// Pre-resolved publication data for one touched free word in a put batch.
///
/// The authoritative atomic reference is resolved before publication begins.
/// The containing summary is shared by all records with the same stripe index.
#[derive(Clone, Copy)]
struct PutRecord<'a> {
    /// Stripe index used for sorting and publication grouping.
    stripe: usize,
    /// Logical free-word index used for sorting and coalescing.
    word: usize,
    /// Authoritative slot bits to publish in `free_word`.
    mask: u64,
    /// Advisory group bit corresponding to this logical word.
    group_mask: u64,
    /// Pre-resolved authoritative free word.
    free_word: &'a AtomicU64,
}

/// Inline-first storage for sparse put-batch publication records.
///
/// The inline variant is intentionally stack-resident. Boxing it would add an
/// allocation to ordinary large-geometry spill batches.
#[allow(clippy::large_enum_variant)]
enum PutRecords<'a> {
    /// Fixed stack storage for ordinary batches.
    Inline {
        /// Record storage whose prefix through `len` is initialized.
        records: [MaybeUninit<PutRecord<'a>>; INLINE_PUT_RECORDS],
        /// Number of initialized entries in `records`.
        len: usize,
    },
    /// Heap storage for a batch larger than the inline capacity.
    Heap(Vec<PutRecord<'a>>),
}

impl<'a> PutRecords<'a> {
    /// Creates an empty inline record stage.
    #[inline(always)]
    const fn new() -> Self {
        Self::Inline {
            records: [MaybeUninit::uninit(); INLINE_PUT_RECORDS],
            len: 0,
        }
    }

    /// Chooses inline or heap storage for an expected record capacity.
    #[inline(always)]
    fn with_capacity(capacity: usize) -> Self {
        if capacity <= INLINE_PUT_RECORDS {
            Self::new()
        } else {
            Self::Heap(Vec::with_capacity(capacity))
        }
    }

    /// Appends one record, promoting the initialized prefix when it overflows.
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

    /// Returns exactly the initialized records as a mutable slice.
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

/// Builds a mask containing the lowest `bits` bits.
///
/// `bits` must be in `1..=64`.
#[inline(always)]
const fn low_bits(bits: usize) -> u64 {
    assert!(bits > 0 && bits <= SLOT_WORD_BITS);
    if bits == SLOT_WORD_BITS {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// Builds the advisory availability mask for one summary group.
#[inline(always)]
const fn group_mask(group: usize) -> u64 {
    1u64 << group
}

/// Encodes a group as the nonzero exact cleaning code in a summary word.
#[inline(always)]
const fn encode_code(group: usize) -> u64 {
    ((group as u64) + 1) << CODE_SHIFT
}

/// Decodes the exact summary cleaning code, with zero representing no cleaner.
#[inline(always)]
const fn decode_code(state: u64) -> Option<usize> {
    let raw = ((state & CODE_MASK) >> CODE_SHIFT) as usize;
    assert!(raw <= AVAILABILITY_BITS);
    if raw == 0 { None } else { Some(raw - 1) }
}

/// Packs a retained probe phase and the next ticket into cursor state.
#[inline(always)]
const fn encode_cursor(probe_phase: u64, next: usize) -> u64 {
    (probe_phase << CURSOR_NEXT_BITS) | next as u64
}

/// Extracts the next creation ticket from packed cursor state.
#[inline(always)]
const fn decode_cursor_next(state: u64) -> usize {
    (state & CURSOR_NEXT_MASK) as usize
}

/// Extracts the retained probe phase from packed cursor state.
#[inline(always)]
const fn decode_cursor_phase(state: u64) -> u64 {
    (state >> CURSOR_NEXT_BITS) & PROBE_PHASE_MASK
}

/// Maps an unreduced word phase uniformly into a nonzero word count.
#[inline(always)]
const fn reduce_word_phase(word_phase: u32, words: usize) -> usize {
    (((word_phase as u64) * (words as u64)) >> WORD_PHASE_BITS) as usize
}

/// Returns the next admitted creation count without overflowing at capacity.
#[inline(always)]
const fn next_admission(created: usize, capacity: usize) -> Option<usize> {
    if created < capacity {
        Some(created + 1)
    } else {
        None
    }
}

/// Mixes a monotonic probe id into independent navigation phase bits.
#[inline(always)]
const fn mix_probe_id(id: u64) -> u64 {
    let mut mixed = id;
    mixed ^= mixed >> 30;
    mixed = mixed.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed ^= mixed >> 27;
    mixed = mixed.wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

/// Asserts that an array of `len` values has a representable allocation layout.
fn assert_allocation<T>(len: usize) {
    Layout::array::<T>(len).expect("freelist allocation must be representable");
}

/// Derives the summary group count and unpaired prefix for a word extent.
///
/// Each leading group owns one `base_chunk_words` chunk. Excess tail chunks
/// are paired so at most `max_groups` groups are required.
fn group_geometry(logical_words: usize, base_chunk_words: usize, max_groups: usize) -> (u32, u32) {
    assert!(max_groups > 0 && max_groups <= AVAILABILITY_BITS);
    let base_chunks = logical_words.div_ceil(base_chunk_words);
    assert!(base_chunks <= max_groups * 2);
    // Every chunk beyond the group budget consumes a second tail chunk. The
    // remaining prefix keeps one chunk per group.
    let paired = base_chunks.saturating_sub(max_groups);
    let single = base_chunks - paired * 2;
    let groups = single + paired;
    assert!(groups > 0 && groups <= max_groups);
    (groups as u32, single as u32)
}

/// Maps a base chunk to its unpaired or paired summary group.
#[inline(always)]
const fn group_for_base(single_groups: usize, base: usize) -> usize {
    if base < single_groups {
        base
    } else {
        single_groups + ((base - single_groups) >> 1)
    }
}

/// Returns the first base chunk and chunk count represented by one group.
#[inline(always)]
const fn group_base_range(single_groups: usize, group: usize) -> (usize, usize) {
    if group < single_groups {
        (group, 1)
    } else {
        (single_groups + (group - single_groups) * 2, 2)
    }
}

/// Internal construction policy for automatic and verification geometries.
#[derive(Clone, Copy)]
struct ConstructionOptions {
    /// Enables summary navigation below the automatic block cutoff.
    force_summaries: bool,
    /// Maximum availability groups exposed by each summary.
    max_groups: usize,
}

impl Default for ConstructionOptions {
    /// Selects automatic traversal policy and the full 58-group geometry.
    fn default() -> Self {
        Self {
            force_summaries: false,
            max_groups: AVAILABILITY_BITS,
        }
    }
}

/// Mutable result state threaded through one bounded take traversal.
struct TakeContext<'a, F> {
    /// Buffers the traversal may still deliver.
    remaining: usize,
    /// Caller callback that receives each claimed buffer.
    on_entry: &'a mut F,
}

impl<F> TakeContext<'_, F> {
    /// Returns whether the requested batch size has been filled.
    #[inline(always)]
    const fn is_full(&self) -> bool {
        self.remaining == 0
    }
}

/// Bounded lock-free freelist of tracked buffers for one size class.
///
/// The freelist owns the [`Layout`] shared by every tracked buffer in the size
/// class. Pooled backing values and thread-local caches may temporarily hold
/// [`PooledBuffer`] handles, but those handles must eventually return here so
/// they can be released with the correct layout. The buffer pool keeps the
/// freelist alive for those outstanding handles with live leases stored in
/// pooled slot entries. Draining or dropping the freelist only deallocates
/// buffers currently parked in it.
///
/// The free set is striped over a power-of-two number of cache-isolated
/// contention domains. Packed free bits authoritatively own parked buffers.
/// Larger layouts use one advisory 58+6 state word per stripe to navigate those
/// free words, while small layouts scan free words directly. Stripe-local
/// monotonic cursors assign lazy creation tickets without a reservation bitmap.
///
/// The module-level documentation gives the complete ownership, geometry,
/// summary, creation, drain, and memory-ordering protocols.
pub struct Freelist {
    /// Allocation layout shared by every tracked buffer.
    layout: Layout,
    /// Fixed total number of stable slots.
    capacity: usize,
    /// Monotonic global admission count for lazy creation.
    created: CachePadded<AtomicUsize>,
    /// Cache-isolated ownership and navigation domains.
    stripes: Box<[CachePadded<Stripe>]>,
    /// Monotonic creation cursor for each stripe.
    creation_cursors: Box<[CachePadded<CreationCursor>]>,
    /// Mask used for wrapped stripe routing.
    stripe_mask: usize,
    /// Shift used to recover a stripe-local index from a global slot id.
    stripe_shift: u32,
    /// Shift for the common power-of-two base summary chunk width.
    base_chunk_shift: u32,
    /// Whether takes navigate through summaries instead of scanning directly.
    summaries_enabled: bool,
}

// SAFETY: each owner entry is mutated only while its authoritative free bit is
// clear and the slot is exclusively owned. Release publication and Acquire
// claims synchronize ownership transfers.
unsafe impl Send for Freelist {}
// SAFETY: the same slot ownership and free-bit synchronization apply to shared
// access. Stripe-local owner pointees remain stable until the freelist drops.
unsafe impl Sync for Freelist {}

/// Construction helpers used by targeted protocol tests.
#[cfg(test)]
pub(super) mod test_helpers {
    use super::*;

    /// Builds a freelist that exercises summary navigation at any capacity.
    pub(in crate::iobuf) fn forced_summary(
        capacity: NonZeroU32,
        parallelism: NonZeroUsize,
        layout: Layout,
        prefill: bool,
    ) -> Freelist {
        Freelist::new_inner(
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
}

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

    /// Builds the complete freelist storage from validated policy options.
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
        // The physical block budget is target-adaptive because block width is
        // derived from the target's production atomic representation.
        let summaries_enabled = options.force_summaries
            || geometry.total_free_word_blocks > MAX_DIRECT_FREE_WORD_BLOCKS;

        assert_allocation::<CachePadded<Stripe>>(geometry.stripe_count);
        assert_allocation::<CachePadded<CreationCursor>>(geometry.stripe_count);

        let mut stripes = Vec::with_capacity(geometry.stripe_count);
        let mut creation_cursors = Vec::with_capacity(geometry.stripe_count);

        // Every owner record and every atomic is initialized before `Self` can
        // be shared. Stripe-local owner slices never move after this loop.
        for stripe_index in 0..geometry.stripe_count {
            let stripe_capacity = geometry.stripe_capacity(stripe_index);
            let logical_words = stripe_capacity.div_ceil(SLOT_WORD_BITS);
            let free_word_blocks = logical_words.div_ceil(FREE_WORDS_PER_BLOCK);
            let (group_count, single_groups) =
                group_geometry(logical_words, geometry.base_chunk_words, options.max_groups);

            assert_allocation::<FreeWordBlock>(free_word_blocks);
            assert_allocation::<CachePadded<UnsafeCell<PooledOwner>>>(stripe_capacity);

            let free_word_blocks = (0..free_word_blocks)
                .map(|block| {
                    let words = std::array::from_fn(|offset| {
                        let logical_word = block * FREE_WORDS_PER_BLOCK + offset;
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
                low_bits(group_count as usize)
            } else {
                0
            };
            // Prefill consumes every creation ticket and advertises every
            // valid group. Empty construction leaves both states at zero.
            let cursor = if prefill {
                encode_cursor(0, stripe_capacity)
            } else {
                0
            };

            stripes.push(CachePadded::new(Stripe {
                summary: AtomicU64::new(summary),
                free_word_blocks,
                slots,
                capacity: stripe_capacity,
                logical_words,
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
            stripe_mask: geometry.stripe_count - 1,
            stripe_shift: geometry.stripe_shift,
            base_chunk_shift: geometry.base_chunk_words.trailing_zeros(),
            summaries_enabled,
        };

        if prefill {
            for (stripe_index, stripe) in freelist.stripes.iter().enumerate() {
                for local in 0..stripe.capacity {
                    // SAFETY: construction exclusively owns every eagerly
                    // initialized owner entry. Free bits are not shared until
                    // construction returns.
                    let _ = unsafe {
                        PooledBuffer::new(freelist.owner_ptr(stripe_index, local), layout, false)
                    };
                }
            }
        }

        freelist
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
            // Unranking uses the cursor's retained phase, keeping creation in
            // the same group-major order that later reuse probes.
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

    /// Decodes a global slot into stripe, local, word, and bit locations.
    #[inline(always)]
    const fn slot_location(&self, slot: u32) -> (usize, usize, usize, u64) {
        let slot = slot as usize;
        let stripe = slot & self.stripe_mask;
        let local = slot >> self.stripe_shift;
        let word = local >> SLOT_WORD_SHIFT;
        let mask = 1u64 << (local & (SLOT_WORD_BITS - 1));
        (stripe, local, word, mask)
    }

    /// Maps one logical free word to its advisory summary group.
    #[inline(always)]
    const fn group_for_word(&self, stripe: &Stripe, word: usize) -> usize {
        let base = word >> self.base_chunk_shift;
        group_for_base(stripe.single_groups as usize, base)
    }

    /// Returns a group's logical word range and its untruncated full width.
    #[inline(always)]
    fn group_word_range(&self, stripe: &Stripe, group: usize) -> (usize, usize, usize) {
        let (base, base_count) = group_base_range(stripe.single_groups as usize, group);
        let start = base << self.base_chunk_shift;
        let full_words = base_count << self.base_chunk_shift;
        let end = start.saturating_add(full_words).min(stripe.logical_words);
        (start, end, full_words)
    }

    /// Counts valid slots represented by one summary group.
    #[inline(always)]
    fn group_slot_count(&self, stripe: &Stripe, group: usize) -> usize {
        let (start, end, _) = self.group_word_range(stripe, group);
        (end * SLOT_WORD_BITS).min(stripe.capacity) - start * SLOT_WORD_BITS
    }

    /// Chooses the probe's starting offset inside a word span.
    #[inline(always)]
    const fn word_offset(probe: Probe, words: usize, full_words: Option<usize>) -> usize {
        if let Some(full_words) = full_words
            && words == full_words
        {
            return probe.word_phase as usize & (full_words - 1);
        }
        reduce_word_phase(probe.word_phase, words)
    }

    /// Maps one stripe-local creation ticket to a phase-affine local slot.
    fn unrank_local(&self, stripe: &Stripe, probe: Probe, mut ticket: usize) -> usize {
        if !self.summaries_enabled {
            return self.unrank_span(stripe, probe, 0, stripe.logical_words, None, ticket);
        }

        let group_count = stripe.group_count as usize;
        // Summarized creation consumes complete groups in wrapped probe order.
        // Singleton and paired groups contribute their exact valid slot count.
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

    /// Unranks a ticket across a word span wrapped at its probe-selected start.
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

    /// Unranks within one contiguous run and returns any unconsumed ticket.
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
            // Full words rotate all 64 bit positions directly. A partial tail
            // instead ranks only its valid bits below.
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
        let free_word = stripe.free_word(word);
        let summary = &stripe.summary;
        let group = group_mask(self.group_for_word(stripe, word));

        let previous = free_word.fetch_or(mask, Ordering::Release);
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
    /// Batch insertion groups returned slots by free word, so each touched word
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

        // Small aggregate geometries validate the complete batch in a dense
        // stack table. Larger geometries stage only touched words, then sort
        // and coalesce them before the first atomic publication.
        let dense_len = self.stripes.len() * self.stripes[0].logical_words;
        if dense_len <= INLINE_FREE_WORD_MASKS {
            let mut masks = MaybeUninit::<[u64; INLINE_FREE_WORD_MASKS]>::uninit();
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
            // Sorting makes every equal stripe and word key contiguous. The
            // mask tie-breaker also makes duplicate slot records adjacent.
            records.sort_unstable_by_key(|record| (record.stripe, record.word, record.mask));
            let len = Self::coalesce_records(records);
            self.publish_records(&records[..len]);
        }
    }

    /// Stages one returned slot in a dense stripe-major free-word table.
    #[inline(always)]
    fn stage_dense(&self, masks: &mut [u64], stride: usize, buffer: PooledBuffer) {
        let (stripe, _, word, mask) = self.slot_location(buffer.slot());
        let index = stripe * stride + word;
        assert_eq!(masks[index] & mask, 0, "duplicate slot in put_batch");
        masks[index] |= mask;
    }

    /// Resolves one returned slot into a sparse publication record.
    #[inline(always)]
    fn stage_record<'a>(&'a self, records: &mut PutRecords<'a>, buffer: PooledBuffer) {
        let (stripe, _, word, mask) = self.slot_location(buffer.slot());
        records.push(self.put_record(stripe, word, mask));
    }

    /// Resolves the masks and authoritative atomic for one word publication.
    #[inline(always)]
    fn put_record(&self, stripe_index: usize, word: usize, mask: u64) -> PutRecord<'_> {
        let stripe = &self.stripes[stripe_index];
        PutRecord {
            stripe: stripe_index,
            word,
            mask,
            group_mask: group_mask(self.group_for_word(stripe, word)),
            free_word: stripe.free_word(word),
        }
    }

    /// Coalesces sorted same-word records and rejects duplicate slot bits.
    ///
    /// Returns the length of the coalesced prefix.
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
            } else {
                records[len] = record;
                len += 1;
            }
        }
        len
    }

    /// Publishes staged words, then advisory groups, in stripe-major order.
    fn publish_records(&self, records: &[PutRecord<'_>]) {
        let Some(first) = records.first() else {
            return;
        };
        let mut stripe = first.stripe;
        let mut summary = &self.stripes[stripe].summary;
        let mut groups = 0u64;
        let mut overlap = 0u64;

        for record in records {
            if record.stripe != stripe {
                // Complete all publication for the previous stripe before
                // validating overlap and advancing to the next stripe.
                if self.summaries_enabled {
                    summary.fetch_or(groups, Ordering::Release);
                }
                assert_eq!(
                    overlap, 0,
                    "returned slot batch must not already contain a free slot"
                );
                stripe = record.stripe;
                // Resolve the next summary before publishing that stripe's
                // first free word, preserving the non-panicking interval.
                summary = &self.stripes[stripe].summary;
                groups = 0;
                overlap = 0;
            }

            overlap |= record.free_word.fetch_or(record.mask, Ordering::Release) & record.mask;
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
    /// The search starts from a stable per-thread home stripe and phase-selected
    /// group and word, then scans other stripes only on miss. Within a word,
    /// `fetch_and` claims one bit. That is important: unlike a full-word CAS
    /// loop, two threads removing different bits from the same word can both
    /// succeed.
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

    /// Scans every stripe once from `probe` until `max` buffers are delivered.
    fn take_with_probe(
        &self,
        probe: Probe,
        max: usize,
        on_entry: &mut impl FnMut(PooledBuffer),
    ) -> usize {
        let mut context = TakeContext {
            remaining: max,
            on_entry,
        };
        for scanned in 0..self.stripes.len() {
            let stripe_index = probe.stripe(scanned, self.stripe_mask);
            let stripe = &self.stripes[stripe_index];
            if self.summaries_enabled {
                let state = stripe.summary.load(Ordering::Acquire);
                self.scan_summarized_stripe_from_state(
                    stripe_index,
                    stripe,
                    state,
                    probe,
                    &mut context,
                );
            } else {
                self.scan_bypass_stripe(stripe_index, stripe, probe, &mut context);
            }
            if context.is_full() {
                break;
            }
        }
        max - context.remaining
    }

    /// Scans all authoritative free words in one direct-mode stripe.
    fn scan_bypass_stripe(
        &self,
        stripe_index: usize,
        stripe: &Stripe,
        probe: Probe,
        context: &mut TakeContext<'_, impl FnMut(PooledBuffer)>,
    ) {
        let mut word = reduce_word_phase(probe.word_phase, stripe.logical_words);
        for _ in 0..stripe.logical_words {
            let candidates = stripe.free_word(word).load(Ordering::Acquire);
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

    /// Scans one stripe from an acquired summary snapshot.
    ///
    /// Low availability bits are advisory candidates. A nonzero high code is
    /// one exact additional group that must be visited or repaired.
    fn scan_summarized_stripe_from_state(
        &self,
        stripe_index: usize,
        stripe: &Stripe,
        state: u64,
        probe: Probe,
        context: &mut TakeContext<'_, impl FnMut(PooledBuffer)>,
    ) {
        if state == 0 {
            return;
        }

        // One pass-local snapshot supplies the low candidates. Later loads may
        // contribute exact coded groups, but never introduce fresh low bits.
        let mut low_pending = state & low_bits(stripe.group_count as usize);
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

            let before = context.remaining;
            self.scan_group(stripe_index, stripe, group, probe, repair, context);
            if context.is_full() {
                return;
            }
            if context.remaining != before {
                continue;
            }

            let current = stripe.summary.load(Ordering::Acquire);
            if Self::try_claim_cleanup(stripe, current, group, processed, &mut code_pending) {
                self.clean_owned_group(stripe_index, stripe, group, probe, context);
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

    /// Adds an exact coded group unless this pass already processed it.
    #[inline(always)]
    fn add_code_candidate(stripe: &Stripe, group: usize, processed: u64, pending: &mut u64) {
        assert!(group < stripe.group_count as usize);
        *pending |= group_mask(group) & !processed;
    }

    /// Attempts to replace one availability bit with its exact cleaning code.
    ///
    /// A foreign code is preserved and added to `code_pending`. The method
    /// returns true only when this caller owns cleanup for `group`.
    #[inline(always)]
    fn try_claim_cleanup(
        stripe: &Stripe,
        current: u64,
        group: usize,
        processed: u64,
        code_pending: &mut u64,
    ) -> bool {
        if let Some(code_group) = decode_code(current) {
            Self::add_code_candidate(stripe, code_group, processed, code_pending);
            return false;
        }

        let mask = group_mask(group);
        if current & mask == 0 {
            return false;
        }

        // The replacement preserves sibling availability while atomically
        // removing only this group's low bit and installing its exact code.
        let desired = (current & AVAILABILITY_MASK & !mask) | encode_code(group);
        match stripe
            .summary
            .compare_exchange(current, desired, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(actual) => {
                if let Some(code_group) = decode_code(actual) {
                    Self::add_code_candidate(stripe, code_group, processed, code_pending);
                }
                false
            }
        }
    }

    /// Scans one summary group and optionally repairs it before each claim.
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
            let candidates = stripe.free_word(word).load(Ordering::Acquire);
            if repair && candidates != 0 {
                // An observer of a foreign code republishes availability before
                // a claim, so clearing the code cannot hide a concurrent put.
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

    /// Validates a group while owning its exact summary cleaning code.
    ///
    /// The first nonzero word is repaired before the code is removed. If every
    /// word is zero, the code is removed while availability stays clear.
    fn clean_owned_group(
        &self,
        stripe_index: usize,
        stripe: &Stripe,
        group: usize,
        probe: Probe,
        context: &mut TakeContext<'_, impl FnMut(PooledBuffer)>,
    ) {
        let mask = group_mask(group);
        let (start, end, full_words) = self.group_word_range(stripe, group);
        let words = end - start;
        let offset = Self::word_offset(probe, words, Some(full_words));
        let mut word = start + offset;

        for visited in 0..words {
            let candidates = stripe.free_word(word).load(Ordering::Acquire);
            if candidates != 0 {
                // Repair availability before removing the exact code. The
                // remaining scan can then use ordinary authoritative claims.
                stripe.summary.fetch_or(mask, Ordering::Release);
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
                    let candidates = stripe.free_word(word).load(Ordering::Acquire);
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

        stripe
            .summary
            .fetch_and(AVAILABILITY_MASK, Ordering::Release);
    }

    /// Claims valid candidate bits and delivers each exclusively owned slot.
    ///
    /// The word value returned by each RMW may add newly published candidates.
    /// `attempted` bounds every physical bit to one attempt in this invocation.
    fn claim_word(
        &self,
        stripe_index: usize,
        stripe: &Stripe,
        word: usize,
        mut candidates: u64,
        probe: Probe,
        context: &mut TakeContext<'_, impl FnMut(PooledBuffer)>,
    ) {
        let valid = stripe.valid_free_word_mask(word);
        candidates &= valid;
        let mut attempted = 0u64;

        while candidates != 0 && !context.is_full() {
            let claim = probe.select_set_bits(candidates, context.remaining);
            attempted |= claim;
            let observed = stripe.free_word(word).fetch_and(!claim, Ordering::Acquire);
            let mut claimed = observed & claim;

            while claimed != 0 {
                let bit = probe.select_set_bit(claimed);
                let local = word * SLOT_WORD_BITS + bit;
                (context.on_entry)(self.buffer(stripe_index, local));
                claimed &= !(1u64 << bit);
                context.remaining -= 1;
            }

            // The returned state enables finite helping for bits published
            // after the candidate load without retrying an attempted bit.
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
    /// Summary words are advisory and are neither consulted nor cleared.
    ///
    /// Returns the number of drained slots.
    #[inline]
    pub fn drain(&self) -> usize {
        let mut drained = 0;

        for (stripe_index, stripe) in self.stripes.iter().enumerate() {
            for word in 0..stripe.logical_words {
                // The Acquire swap claims authoritative ownership of every set
                // bit. Advisory summaries are intentionally left untouched.
                let mut claimed = stripe.free_word(word).swap(0, Ordering::Acquire);

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

    /// Returns the stable non-null owner pointer for one stripe-local slot.
    #[inline(always)]
    fn owner_ptr(&self, stripe: usize, local: usize) -> ptr::NonNull<PooledOwner> {
        let cell = self.stripes[stripe]
            .slots
            .get(local)
            .expect("slot id must refer to an allocated slot");

        // Both access paths address the same stable boxed owner slice. Loom's
        // UnsafeCell API exposes the pointer only inside its tracking closure.
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
    /// Drains parked allocations before stable owner storage is released.
    fn drop(&mut self) {
        // Any slot still free in the freelist owns a live pooled allocation.
        // Drain it explicitly before the side-table storage goes away.
        self.drain();
    }
}

/// Raw and mixed forms of one thread's stable probe identity.
#[derive(Clone, Copy)]
struct ProbeId {
    /// Monotonic id whose low bits choose the home stripe.
    raw: usize,
    /// Mixed id whose fields supply local navigation phases.
    mixed: u64,
}

/// Stable home stripe and cyclic navigation phases for one operation.
#[derive(Clone, Copy)]
struct Probe {
    /// First stripe visited by this thread.
    home_stripe: usize,
    /// Unreduced six-bit starting phase for summary groups.
    group_phase: u32,
    /// Unreduced 27-bit starting phase for free words.
    word_phase: u32,
    /// Six-bit rotation applied to slot selection within a free word.
    bit_phase: u32,
}

cfg_if::cfg_if! {
    if #[cfg(not(feature = "loom"))] {
        /// Monotonic process-wide source for per-thread probe ids.
        static NEXT_PROBE_ID: AtomicUsize = AtomicUsize::new(0);
    } else {
        loom::lazy_static! {
            /// Monotonic modeled source for per-thread probe ids.
            static ref NEXT_PROBE_ID: AtomicUsize = AtomicUsize::new(0);
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(feature = "loom"))] {
        thread_local! {
            /// Lazily assigned stable probe identity for this native thread.
            static TLS_PROBE_ID: Cell<Option<ProbeId>> = const { Cell::new(None) };
        }
    } else {
        loom::thread_local! {
            /// Lazily assigned stable probe identity for this modeled thread.
            static TLS_PROBE_ID: Cell<Option<ProbeId>> = Cell::new(None);
        }
    }
}

impl Probe {
    /// Returns the current thread's stable probe for a stripe geometry.
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

    /// Decodes a raw and mixed identity for the supplied stripe mask.
    #[inline(always)]
    const fn from_id(id: ProbeId, stripe_mask: usize) -> Self {
        Self {
            home_stripe: id.raw & stripe_mask,
            group_phase: (id.mixed & 63) as u32,
            bit_phase: ((id.mixed >> 6) & 63) as u32,
            word_phase: ((id.mixed >> 12) & WORD_PHASE_MASK) as u32,
        }
    }

    /// Rebuilds a probe from a retained phase and explicit home stripe.
    #[inline(always)]
    const fn from_phase(home_stripe: usize, phase: u64) -> Self {
        Self {
            home_stripe,
            group_phase: (phase & 63) as u32,
            bit_phase: ((phase >> 6) & 63) as u32,
            word_phase: ((phase >> 12) & WORD_PHASE_MASK) as u32,
        }
    }

    /// Packs the group, bit, and word phases for creation-cursor retention.
    #[inline(always)]
    const fn phase(self) -> u64 {
        self.group_phase as u64 | ((self.bit_phase as u64) << 6) | ((self.word_phase as u64) << 12)
    }

    /// Returns the `scanned`th stripe in wrapped order from the home stripe.
    #[inline(always)]
    const fn stripe(self, scanned: usize, stripe_mask: usize) -> usize {
        (self.home_stripe + scanned) & stripe_mask
    }

    /// Returns the `offset`th group in wrapped order from the group phase.
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

    /// Selects the first set group at or after the phase-derived start.
    #[inline(always)]
    const fn select_group(self, groups: u64, group_count: usize) -> usize {
        let start = (self.group_phase as usize * group_count) >> 6;
        // Rotation makes trailing-zero selection cyclic from the reduced home
        // group without iterating over absent groups.
        let rotated = groups.rotate_right(start as u32);
        ((rotated.trailing_zeros() as usize) + start) & (SLOT_WORD_BITS - 1)
    }

    /// Selects the first set slot bit at or after the bit phase.
    #[inline(always)]
    const fn select_set_bit(self, word: u64) -> usize {
        let rotated = word.rotate_right(self.bit_phase);
        ((rotated.trailing_zeros() + self.bit_phase) & (SLOT_WORD_BITS as u32 - 1)) as usize
    }

    /// Selects up to `limit` set bits in cyclic order from the bit phase.
    #[inline]
    const fn select_set_bits(self, word: u64, limit: usize) -> u64 {
        // Select in the rotated coordinate system, then restore physical bit
        // positions for the authoritative fetch-and mask.
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

    /// Selects a zero-based set-bit rank after rotating from the bit phase.
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

/// Native unit tests and read-only test inspection helpers.
#[cfg(all(test, not(feature = "loom")))]
pub(super) mod tests {
    use super::*;
    use commonware_utils::{NZU32, NZUsize};
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize as StdAtomicUsize, Ordering as AtomicOrdering},
    };

    /// Returns the number of lazy-creation permits that have been admitted.
    pub fn created(freelist: &Freelist) -> usize {
        freelist.created.load(Ordering::Relaxed)
    }

    /// Counts authoritative free bits across all logical words.
    pub fn len(freelist: &Freelist) -> usize {
        freelist
            .stripes
            .iter()
            .map(|stripe| {
                (0..stripe.logical_words)
                    .map(|word| {
                        stripe.free_word(word).load(Ordering::Acquire).count_ones() as usize
                    })
                    .sum::<usize>()
            })
            .sum()
    }

    /// Counts logical free words across all stripes.
    pub fn num_words(freelist: &Freelist) -> usize {
        freelist
            .stripes
            .iter()
            .map(|stripe| stripe.logical_words)
            .sum()
    }

    /// Returns the constructed stripe count.
    pub fn num_stripes(freelist: &Freelist) -> usize {
        freelist.stripes.len()
    }

    /// Maps a stripe-local test coordinate to a global slot id.
    const fn slot_index(freelist: &Freelist, stripe: usize, local: usize) -> u32 {
        ((local << freelist.stripe_shift) | stripe) as u32
    }

    /// Resolves a test slot id to its stable owner pointer.
    fn slot_ptr(freelist: &Freelist, slot: u32) -> ptr::NonNull<PooledOwner> {
        let (stripe, local, _, _) = freelist.slot_location(slot);
        freelist.owner_ptr(stripe, local)
    }

    /// Creates every slot and returns buffers indexed by their stable slot ids.
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

    /// Shared nonzero cache-aligned allocation layout for native tests.
    const TEST_LAYOUT: Layout = match Layout::from_size_align(64, 64) {
        Ok(layout) => layout,
        Err(_) => unreachable!(),
    };

    /// Builds metadata-only freelist state for pure group-mapping tests.
    fn mapping_shell(base_chunk_words: usize) -> Freelist {
        Freelist {
            layout: TEST_LAYOUT,
            capacity: 0,
            created: CachePadded::new(AtomicUsize::new(0)),
            stripes: Vec::<CachePadded<Stripe>>::new().into_boxed_slice(),
            creation_cursors: Vec::<CachePadded<CreationCursor>>::new().into_boxed_slice(),
            stripe_mask: 0,
            stripe_shift: 0,
            base_chunk_shift: base_chunk_words.trailing_zeros(),
            summaries_enabled: true,
        }
    }

    /// Builds metadata-only stripe state for pure group-mapping tests.
    fn mapping_stripe(capacity: usize, base_chunk_words: usize) -> Stripe {
        let logical_words = capacity.div_ceil(SLOT_WORD_BITS);
        let (group_count, single_groups) =
            group_geometry(logical_words, base_chunk_words, AVAILABILITY_BITS);
        Stripe {
            summary: AtomicU64::new(0),
            free_word_blocks: Vec::new().into_boxed_slice(),
            slots: Vec::new().into_boxed_slice(),
            capacity,
            logical_words,
            group_count,
            single_groups,
        }
    }

    /// Verifies stripe bounds across capacity and parallelism extremes.
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
                let (groups, _) =
                    group_geometry(logical_words, geometry.base_chunk_words, AVAILABILITY_BITS);
                assert!(groups <= AVAILABILITY_BITS as u32);
                assert_eq!(low_bits(groups as usize) & CODE_MASK, 0);
            }
        }
    }

    /// Verifies logical word counts at slot and word boundaries.
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

    /// Verifies concentrated and scattered aggregate block accounting.
    #[test]
    fn test_geometry_counts_aggregate_free_word_blocks() {
        for blocks in [15, 16, 17, 31, 32, 33] {
            let capacity = blocks * FREE_WORDS_PER_BLOCK * SLOT_WORD_BITS;
            let concentrated = Geometry::new(capacity, 1);
            assert_eq!(concentrated.total_free_word_blocks, blocks);

            let stripes = 1usize << blocks.ilog2();
            let extra_blocks = blocks - stripes;
            let scattered_capacity = stripes * FREE_WORDS_PER_BLOCK * SLOT_WORD_BITS + extra_blocks;
            let scattered = Geometry::new(scattered_capacity, stripes);
            assert_eq!(scattered.stripe_count, stripes);
            assert_eq!(scattered.total_free_word_blocks, blocks);
        }
    }

    /// Verifies target-neutral automatic policy at the 32 and 33 block boundary.
    #[test]
    fn test_freelist_automatic_policy_switches_after_aggregate_block_cutoff() {
        for (blocks, expected_summaries) in [(32, false), (33, true)] {
            let concentrated = blocks * FREE_WORDS_PER_BLOCK * SLOT_WORD_BITS;
            let stripes = 1usize << blocks.ilog2();
            let extra_blocks = blocks - stripes;
            let scattered = stripes * FREE_WORDS_PER_BLOCK * SLOT_WORD_BITS + extra_blocks;

            for (capacity, parallelism) in [(concentrated, 1), (scattered, stripes)] {
                let geometry = Geometry::new(capacity, parallelism);
                assert_eq!(geometry.total_free_word_blocks, blocks);

                let capacity = NonZeroU32::new(
                    u32::try_from(capacity).expect("policy boundary capacity must fit in u32"),
                )
                .expect("policy boundary capacity must be non-zero");
                let parallelism = NonZeroUsize::new(parallelism)
                    .expect("policy boundary parallelism must be non-zero");
                let freelist = Freelist::new(capacity, parallelism, TEST_LAYOUT, false);
                assert_eq!(freelist.summaries_enabled, expected_summaries);
            }
        }
    }

    /// Verifies that only excess tail chunks are paired into summary groups.
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
                let (groups, single) = group_geometry(logical_words, 4, AVAILABILITY_BITS);
                assert_eq!(groups as usize, expected_groups);
                assert_eq!(single as usize, expected_single);

                for base in 0..base_chunks {
                    let group = group_for_base(expected_single, base);
                    let (first, count) = group_base_range(expected_single, group);
                    assert!(base >= first && base < first + count);
                }
            }
        }
    }

    /// Verifies packed masks, cleaning codes, and overflow-safe admission.
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

    /// Verifies cursor packing and group-major creation bijections.
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

    /// Verifies that creation retains the full word phase across group widths.
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

    /// Verifies fixed probe prefixes stay within their selected first group.
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

    /// Verifies lazy creation capacity and eager prefill state.
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

    /// Verifies forced summary publication and settled-empty cleanup.
    #[test]
    fn test_freelist_forced_summary_publishes_and_cleans() {
        let set = test_helpers::forced_summary(NZU32!(2), NZUsize!(1), TEST_LAYOUT, false);
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

    /// Verifies batch summary publication and overlap detection ordering.
    #[test]
    fn test_freelist_summary_batch_publication_and_overlap_panic() {
        let set = test_helpers::forced_summary(NZU32!(3), NZUsize!(1), TEST_LAYOUT, false);
        let mut entries = reserve_by_slot(&set, 3);
        let first = entries[0].take().unwrap();
        let second = entries[1].take().unwrap();
        let first_slot = first.slot();

        // SAFETY: this duplicate exists only to exercise the post-publication
        // overlap assertion. The original handle is published first.
        let duplicate = unsafe { PooledBuffer::from_owner(slot_ptr(&set, first_slot)) };
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

    /// Verifies a cleaning-code observer repairs availability before claiming.
    #[test]
    fn test_freelist_summary_code_observer_repairs_before_claim() {
        let set = test_helpers::forced_summary(NZU32!(1), NZUsize!(1), TEST_LAYOUT, false);
        let buffer = set.try_create(false).expect("slot");
        let stripe = &set.stripes[0];

        // Seed the constructor-exclusive state that an active cleaner exposes.
        stripe.free_word(0).store(1, Ordering::Relaxed);
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

    /// Verifies drain never mutates advisory summary state.
    #[test]
    fn test_freelist_drain_preserves_summary_state() {
        let set = test_helpers::forced_summary(NZU32!(2), NZUsize!(1), TEST_LAYOUT, true);
        let before = set.stripes[0].summary.load(Ordering::Acquire);
        assert_ne!(before, 0);
        assert_eq!(set.drain(), 2);
        assert_eq!(set.stripes[0].summary.load(Ordering::Acquire), before);
        assert!(set.take().is_none());
        assert_eq!(set.stripes[0].summary.load(Ordering::Acquire), 0);
    }

    /// Verifies a forced paired group reaches both base chunks.
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

    /// Verifies single puts reject a slot that is already free.
    #[test]
    #[should_panic(expected = "returned slot must not already be marked free")]
    fn test_freelist_put_rejects_double_return() {
        let set = Freelist::new(NZU32!(1), NZUsize!(1), TEST_LAYOUT, false);
        let buffer = set.try_create(false).expect("slot available");
        // SAFETY: the duplicate handle exists only to drive the double-return
        // assert. The second put panics before it is used further, and drain
        // deallocates the slot exactly once afterwards.
        let duplicate = unsafe { PooledBuffer::from_owner(slot_ptr(&set, 0)) };
        set.put(buffer);
        set.put(duplicate);
    }

    /// Verifies batch puts reject a slot that was already free.
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
        let duplicate = unsafe { PooledBuffer::from_owner(slot_ptr(&set, returned_slot)) };
        set.put(returned);
        set.put_batch([other, duplicate]);
    }

    /// Verifies batch staging rejects duplicate slots before publication.
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
        let duplicate = unsafe { PooledBuffer::from_owner(slot_ptr(&set, slot)) };
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
        set.put(unsafe { PooledBuffer::from_owner(slot_ptr(&set, slot)) });
    }

    /// Verifies every available slot is transferred exactly once.
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

    /// Verifies creation follows the current thread's probe order.
    #[test]
    fn test_freelist_try_create_uses_thread_probe_order() {
        // Lazy creation follows the same group, word, and bit phases as reuse.
        let set = Freelist::new(NZU32!(512), NZUsize!(8), TEST_LAYOUT, false);
        let probe = Probe::new(set.stripe_mask);
        let stripe_index = probe.home_stripe;
        let stripe = &set.stripes[stripe_index];

        let expected0 = slot_index(&set, stripe_index, set.unrank_local(stripe, probe, 0));
        let expected1 = slot_index(&set, stripe_index, set.unrank_local(stripe, probe, 1));

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

    /// Verifies concurrent creators reserve distinct stable slots.
    #[test]
    fn test_freelist_concurrent_try_create_reserves_unique_slots() {
        /// Capacity used to force repeated cursor contention across workers.
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

    /// Verifies stripe counts remain bounded powers of two.
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
                assert_eq!(slot_index(&set, stripe, local), slot);
            }

            for (stripe_index, stripe) in set.stripes.iter().enumerate() {
                assert_eq!(stripe.slots.len(), stripe.capacity);
                for local in 0..stripe.capacity {
                    let slot = slot_index(&set, stripe_index, local);
                    assert_eq!(slot_ptr(&set, slot), set.owner_ptr(stripe_index, local));
                }
            }
        }
    }

    /// Verifies empty, single-entry, and multi-entry batch paths.
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

    /// Verifies large geometries use touched-only sparse batch records.
    #[test]
    fn test_freelist_put_batch_uses_sparse_records_for_large_free_word_layout() {
        let set = Freelist::new(NZU32!(8193), NZUsize!(65), TEST_LAYOUT, false);
        assert!(set.stripes.len() * set.stripes[0].logical_words > INLINE_FREE_WORD_MASKS);
        assert!(num_words(&set) > INLINE_FREE_WORD_MASKS);

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

    /// Verifies heap-backed staging rejects duplicates before publication.
    #[test]
    fn test_freelist_heap_batch_rejects_duplicate_before_publication() {
        let set = Freelist::new(NZU32!(8193), NZUsize!(65), TEST_LAYOUT, false);
        assert!(set.stripes.len() * set.stripes[0].logical_words > INLINE_FREE_WORD_MASKS);

        let mut batch = Vec::with_capacity(INLINE_PUT_RECORDS + 2);
        let mut slots = Vec::with_capacity(INLINE_PUT_RECORDS + 1);
        for _ in 0..=INLINE_PUT_RECORDS {
            let buffer = set.try_create(false).expect("heap batch slot");
            slots.push(buffer.slot());
            batch.push(buffer);
        }

        // SAFETY: this alias exists only to prove that the heap-backed staging
        // path rejects a complete-input duplicate before publishing any free bit.
        batch.push(unsafe { PooledBuffer::from_owner(slot_ptr(&set, slots[0])) });
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            set.put_batch(batch);
        }));
        assert!(panic.is_err());
        assert_eq!(len(&set), 0);

        let restored = slots.iter().map(|&slot| {
            // SAFETY: staging panicked before publication. Each slot was
            // created by this freelist and appears exactly once in `slots`.
            unsafe { PooledBuffer::from_owner(slot_ptr(&set, slot)) }
        });
        set.put_batch(restored);

        let mut taken = Vec::new();
        assert_eq!(
            set.take_batch(INLINE_PUT_RECORDS + 1, |buffer| taken.push(buffer)),
            INLINE_PUT_RECORDS + 1
        );
        let mut observed = taken.iter().map(PooledBuffer::slot).collect::<Vec<_>>();
        observed.sort_unstable();
        slots.sort_unstable();
        assert_eq!(observed, slots);
        for buffer in taken {
            set.put(buffer);
        }
    }

    /// Verifies drain claims and releases every globally available slot.
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

    /// Verifies zero, single, and partial batch-take results.
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

    /// Verifies a filled batch stops within the home word.
    #[test]
    fn test_freelist_take_batch_breaks_after_filling_target_in_home_word() {
        let set = Freelist::new(NZU32!(16), NZUsize!(8), TEST_LAYOUT, true);
        let home = Probe::new(set.stripe_mask).home_stripe;
        let slot0 = slot_index(&set, home, 0);
        let slot1 = slot_index(&set, home, 1);

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

    /// Verifies a word claim honors a batch limit smaller than occupancy.
    #[test]
    fn test_freelist_take_batch_stops_mid_word_when_limit_is_reached() {
        let set = Freelist::new(NZU32!(24), NZUsize!(8), TEST_LAYOUT, true);
        let home = Probe::new(set.stripe_mask).home_stripe;
        // This thread's first probed word contains three slots, so the batch
        // claim has to stop after clearing only the requested number of bits.
        let slots = [
            slot_index(&set, home, 0),
            slot_index(&set, home, 1),
            slot_index(&set, home, 2),
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

    /// Verifies probe rotations, ranks, and selection limits.
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

    /// Verifies stable mixer vectors and decoded probe fields.
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

    /// Verifies stale same-bit candidates cannot duplicate ownership.
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

    /// Verifies dropping a freelist drains all parked buffers.
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

/// Exhaustive Loom models for ownership transfer and summary navigation.
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
        /// One Loom-tracked non-atomic cell per modeled slot.
        cells: Vec<UnsafeCell<usize>>,
    }

    // SAFETY: cross-thread access is what the stamps exist to check. Loom
    // tracks every access made through `UnsafeCell::with`/`with_mut`.
    unsafe impl Send for SlotStamps {}
    // SAFETY: as above.
    unsafe impl Sync for SlotStamps {}

    impl SlotStamps {
        /// Allocates zeroed stamps for `slots` modeled owners.
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
    // striped scans across independent bitmap words, stale Acquire candidate
    // loads, and the Release/Acquire edge that transfers slot ownership after
    // its bit is claimed. Geometry-matrix tests cover single-word/single-bit,
    // single-word/multi-bit, multi-word/single-bit, and multi-word/multi-bit
    // layouts so both degenerate and striped cases stay exercised.

    /// Builds a one-stripe direct-mode freelist for compact ownership models.
    fn single_word_freelist(capacity: u32) -> Freelist {
        let layout = Layout::from_size_align(64, 64).unwrap();
        Freelist::new(NZU32!(capacity), NZUsize!(1), layout, false)
    }

    /// Builds a one-stripe summarized freelist for targeted summary models.
    fn forced_summary_freelist(capacity: u32) -> Freelist {
        let layout = Layout::from_size_align(64, 64).unwrap();
        test_helpers::forced_summary(NZU32!(capacity), NZUsize!(1), layout, false)
    }

    /// Performs a put's free-word RMW while delaying summary publication.
    ///
    /// `PooledBuffer` has no drop glue, so the set free bit owns the allocation
    /// when this helper returns.
    fn stall_put_after_free_word(freelist: &Freelist, buffer: PooledBuffer) -> (usize, u64) {
        let (stripe_index, _, word, mask) = freelist.slot_location(buffer.slot());
        let stripe = &freelist.stripes[stripe_index];
        let previous = stripe.free_word(word).fetch_or(mask, Ordering::Release);
        assert_eq!(previous & mask, 0);
        (
            stripe_index,
            group_mask(freelist.group_for_word(stripe, word)),
        )
    }

    /// Claims one known published slot without advisory navigation.
    ///
    /// Returned-state models use this to place exact free-word transitions
    /// around one real `claim_word` invocation.
    fn claim_published_slot(freelist: &Freelist, slot: u32) -> PooledBuffer {
        let (stripe_index, local, word, mask) = freelist.slot_location(slot);
        let stripe = &freelist.stripes[stripe_index];
        let previous = stripe.free_word(word).fetch_and(!mask, Ordering::Acquire);
        assert_ne!(previous & mask, 0);
        freelist.buffer(stripe_index, local)
    }

    /// Proves a completed put remains discoverable through an exact cleaning code.
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
            assert_ne!(stripe.free_word(0).load(Ordering::Acquire), 0);
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
            // can clear the published free bit, so an empty pass would leave
            // that completed publication set throughout the pass.
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

    /// Proves a later put helps publish a return delayed before summary publication.
    #[test]
    fn summary_second_put_publishes_while_first_is_delayed() {
        loom::model(|| {
            let set = Arc::new(forced_summary_freelist(2));
            let mut entries = Leases::entries(&set);
            let second_buffer = entries.pop().unwrap();
            let delayed_buffer = entries.pop().unwrap();
            assert!(entries.pop().is_none());

            let (free_word_ready_tx, free_word_ready_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let delayed = {
                let set = Arc::clone(&set);
                thread::spawn(move || {
                    let (_, group) = stall_put_after_free_word(&set, delayed_buffer);
                    free_word_ready_tx.send(group).unwrap();
                    resume_rx.recv().unwrap();
                    set.stripes[0].summary.fetch_or(group, Ordering::Release);
                })
            };

            let group = free_word_ready_rx.recv().unwrap();
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

            // Both slots share one free word. The second put must publish the
            // group even though the first put already made that word nonzero.
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

    /// Proves competing takers safely converge one stale advertised group.
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

    /// Proves a code observer repairs navigation before exposing a claimed buffer.
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

    /// Proves batch publication composes with a concurrent summarized take.
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

    /// Proves batch publication survives concurrent stale-group cleanup.
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
            // batch's free-word publications and its final summary publication.
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

    /// Proves overlap panic handling conserves a concurrently claimed free bit.
    #[test]
    fn summary_batch_overlap_panic_conserves_concurrently_claimed_free_bit() {
        loom::model(|| {
            let set = Arc::new(forced_summary_freelist(2));
            let mut entries = Leases::entries(&set);
            entries.sort_unstable_by_key(PooledBuffer::slot);
            let duplicate = entries.remove(0);
            let unique = entries.remove(0);
            let duplicate_slot = duplicate.slot();
            let unique_slot = unique.slot();
            let (stripe_index, duplicate_local, word, duplicate_mask) =
                set.slot_location(duplicate_slot);
            let (_, _, unique_word, unique_mask) = set.slot_location(unique_slot);
            assert_eq!(word, unique_word);
            assert_eq!(duplicate_mask & unique_mask, 0);

            // SAFETY: this alias exists only to exercise the overlap unwind
            // after the same RMW publishes the distinct unique slot.
            let duplicate_alias =
                unsafe { PooledBuffer::from_owner(set.owner_ptr(stripe_index, duplicate_local)) };
            set.put(duplicate);

            let (writer_done_tx, writer_done_rx) = mpsc::channel();
            let writer = {
                let set = Arc::clone(&set);
                thread::spawn(move || {
                    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        set.put_batch([unique, duplicate_alias]);
                    }));
                    assert!(panic.is_err());
                    writer_done_tx.send(()).unwrap();
                })
            };

            let leases = Leases::new(Arc::clone(&set));
            let seen = Arc::new(AtomicUsize::new(0));
            let taker = {
                let set = Arc::clone(&set);
                let leases = Arc::clone(&leases);
                let seen = Arc::clone(&seen);
                thread::spawn(move || {
                    let mut candidates = set.stripes[stripe_index]
                        .free_word(word)
                        .load(Ordering::Acquire)
                        & unique_mask;
                    if candidates == 0 {
                        writer_done_rx.recv().unwrap();
                        candidates = set.stripes[stripe_index]
                            .free_word(word)
                            .load(Ordering::Acquire)
                            & unique_mask;
                    }

                    let mut on_entry = |buffer| {
                        leases.push_expected(&seen, 1usize << unique_slot, buffer);
                    };
                    let mut context = TakeContext {
                        remaining: 1,
                        on_entry: &mut on_entry,
                    };
                    set.claim_word(
                        stripe_index,
                        &set.stripes[stripe_index],
                        word,
                        candidates,
                        Probe::from_phase(stripe_index, 0),
                        &mut context,
                    );
                    assert_eq!(context.remaining, 0);
                })
            };

            writer.join().unwrap();
            taker.join().unwrap();
            while let Some(buffer) = set.take() {
                leases.push_expected(&seen, 0b11, buffer);
            }
            assert_eq!(seen.load(Ordering::Relaxed), 0b11);
            assert_eq!(set.stripes[0].summary.load(Ordering::Acquire), 0);
        });
    }

    /// Proves a code owner repairs and clears navigation before callback delivery.
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

            let (free_word_ready_tx, free_word_ready_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let publisher = {
                let set = Arc::clone(&set);
                thread::spawn(move || {
                    let (_, published_group) = stall_put_after_free_word(&set, buffer);
                    free_word_ready_tx.send(published_group).unwrap();
                    resume_rx.recv().unwrap();
                    set.stripes[0]
                        .summary
                        .fetch_or(published_group, Ordering::Release);
                })
            };

            assert_eq!(free_word_ready_rx.recv().unwrap(), group);
            let mut claimed = None;
            {
                let mut on_entry = |buffer| {
                    let state = stripe.summary.load(Ordering::Acquire);
                    assert_eq!(state & group, group);
                    assert_eq!(decode_code(state), None);
                    claimed = Some(buffer);
                };
                let mut context = TakeContext {
                    remaining: 1,
                    on_entry: &mut on_entry,
                };
                set.clean_owned_group(0, stripe, 0, Probe::from_phase(0, 0), &mut context);
                assert_eq!(context.remaining, 0);
            }

            resume_tx.send(()).unwrap();
            publisher.join().unwrap();
            set.put(claimed.expect("the code owner must claim the published free bit"));
        });
    }

    /// Proves competing code observers deliver one candidate at most once.
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

    /// Proves code observation and drain partition ownership without loss.
    #[test]
    fn summary_code_observer_and_drain_conserve_the_free_bit() {
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

            // The observer may have conservatively repaired the low bit even if
            // drain won the free bit. Removing the manually installed code must
            // preserve that low state for ordinary cleanup.
            stripe
                .summary
                .fetch_and(AVAILABILITY_MASK, Ordering::Release);
            assert!(set.take().is_none());
            assert_eq!(stripe.summary.load(Ordering::Acquire), 0);
        });
    }

    /// Proves observer repair and a live put survive code removal after drain.
    #[test]
    fn summary_observer_repair_and_live_put_survive_code_clear_after_drain() {
        loom::model(|| {
            let set = forced_summary_freelist(2);
            let mut entries = Leases::entries(&set);
            entries.sort_unstable_by_key(PooledBuffer::slot);
            let drained_buffer = entries.remove(0);
            let live_buffer = entries.remove(0);
            let live_slot = live_buffer.slot();
            set.put(drained_buffer);

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

            let candidates = stripe.free_word(0).load(Ordering::Acquire);
            assert_ne!(candidates, 0);
            assert_eq!(set.drain(), 1);

            // Continue the observer from its pass-local candidate load. Drain
            // wins the free bit, so repair must precede a losing claim.
            stripe.summary.fetch_or(group, Ordering::Release);
            let mut unexpected = 0;
            let mut on_entry = |_| unexpected += 1;
            let mut context = TakeContext {
                remaining: 1,
                on_entry: &mut on_entry,
            };
            set.claim_word(
                0,
                stripe,
                0,
                candidates,
                Probe::from_phase(0, 0),
                &mut context,
            );
            assert_eq!(context.remaining, 1);
            assert_eq!(unexpected, 0);

            set.put(live_buffer);
            stripe
                .summary
                .fetch_and(AVAILABILITY_MASK, Ordering::Release);
            assert_eq!(stripe.summary.load(Ordering::Acquire) & group, group);

            let recovered = set
                .take()
                .expect("the later publication must remain visible");
            assert_eq!(recovered.slot(), live_slot);
            set.put(recovered);
        });
    }

    /// Proves a successor cleaner cannot be erased by a prior stale claimant.
    #[test]
    fn summary_successor_cleaner_finishes_before_prior_stale_claim() {
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
            let prior_candidates = stripe.free_word(0).load(Ordering::Acquire);
            assert_ne!(prior_candidates, 0);
            assert_eq!(set.drain(), 1);

            // The prior owner observed a nonzero free word before drain. It
            // repairs and clears its generation before using that stale mask.
            stripe.summary.fetch_or(group, Ordering::Release);
            stripe
                .summary
                .fetch_and(AVAILABILITY_MASK, Ordering::Release);
            assert_eq!(stripe.summary.load(Ordering::Acquire), group);

            // A successor owns and validates the same group while the prior
            // owner is paused before its first claim.
            assert_eq!(
                stripe.summary.compare_exchange(
                    group,
                    encode_code(0),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ),
                Ok(group)
            );
            let mut successor_claims = 0;
            let mut successor = |_| successor_claims += 1;
            let mut successor_context = TakeContext {
                remaining: 1,
                on_entry: &mut successor,
            };
            set.clean_owned_group(
                0,
                stripe,
                0,
                Probe::from_phase(0, 0),
                &mut successor_context,
            );
            assert_eq!(successor_context.remaining, 1);
            assert_eq!(successor_claims, 0);
            assert_eq!(stripe.summary.load(Ordering::Acquire), 0);

            let mut prior_claims = 0;
            let mut prior = |_| prior_claims += 1;
            let mut prior_context = TakeContext {
                remaining: 1,
                on_entry: &mut prior,
            };
            set.claim_word(
                0,
                stripe,
                0,
                prior_candidates,
                Probe::from_phase(0, 0),
                &mut prior_context,
            );
            assert_eq!(prior_context.remaining, 1);
            assert_eq!(prior_claims, 0);
            assert!(set.take().is_none());
        });
    }

    /// Proves a foreign code observed after failed cleanup is scanned once.
    #[test]
    fn summary_foreign_code_from_failed_cleanup_load_is_scanned_once() {
        loom::model(|| {
            let layout = Layout::from_size_align(64, 64).unwrap();
            let set = Arc::new(Freelist::new_inner(
                NZU32!(65),
                NZUsize!(1),
                layout,
                true,
                ConstructionOptions {
                    force_summaries: true,
                    max_groups: 2,
                },
            ));
            let stripe = &set.stripes[0];
            assert_eq!(stripe.group_count, 2);
            assert_eq!(stripe.single_groups, 2);

            let leases = Leases::new(Arc::clone(&set));
            let mut entries = Vec::new();
            assert_eq!(set.take_batch(65, |buffer| entries.push(buffer)), 65);
            let mut target = None;
            for buffer in entries {
                if buffer.slot() == 64 {
                    target = Some(buffer);
                } else {
                    leases.push(buffer);
                }
            }
            assert!(set.take().is_none());

            set.put(target.expect("second-group slot"));
            let first = group_mask(0);
            let second = group_mask(1);
            stripe.summary.fetch_or(first, Ordering::Release);
            let snapshot = stripe.summary.load(Ordering::Acquire);
            assert_eq!(snapshot & (first | second), first | second);

            let coded = (snapshot & AVAILABILITY_MASK & !second) | encode_code(1);
            assert_eq!(
                stripe.summary.compare_exchange(
                    snapshot,
                    coded,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ),
                Ok(snapshot)
            );

            let mut claimed = None;
            let mut on_entry = |buffer| {
                let state = stripe.summary.load(Ordering::Acquire);
                assert_eq!(state & (first | second), first | second);
                assert_eq!(decode_code(state), Some(1));
                claimed = Some(buffer);
            };
            let mut context = TakeContext {
                remaining: 1,
                on_entry: &mut on_entry,
            };
            set.scan_summarized_stripe_from_state(
                0,
                stripe,
                snapshot,
                Probe::from_phase(0, 0),
                &mut context,
            );
            assert_eq!(context.remaining, 0);

            stripe
                .summary
                .fetch_and(AVAILABILITY_MASK, Ordering::Release);
            assert_eq!(
                stripe.summary.load(Ordering::Acquire) & (first | second),
                first | second
            );
            set.put(claimed.expect("the foreign coded group must be scanned"));
            drop(leases);
        });
    }

    /// Proves a failed cleanup CAS contributes the returned foreign code.
    #[test]
    fn summary_failed_cleanup_cas_contributes_returned_foreign_code() {
        // Capture group 0's cleanup state, then let a competing cleaner replace
        // group 1's notification with its exact code. The real one-shot cleanup
        // helper must lose its stale CAS and contribute only the returned code.
        loom::model(|| {
            let layout = Layout::from_size_align(64, 64).unwrap();
            let set = Arc::new(Freelist::new_inner(
                NZU32!(65),
                NZUsize!(1),
                layout,
                true,
                ConstructionOptions {
                    force_summaries: true,
                    max_groups: 2,
                },
            ));
            let stripe = &set.stripes[0];
            assert_eq!(stripe.group_count, 2);

            let leases = Leases::new(Arc::clone(&set));
            assert_eq!(stripe.free_word(0).swap(0, Ordering::Acquire), u64::MAX);
            for local in 0..64 {
                leases.push(set.buffer(0, local));
            }
            assert_eq!(stripe.free_word(1).swap(0, Ordering::Acquire), 1);
            let target = set.buffer(0, 64);
            stripe.summary.fetch_and(0, Ordering::Release);

            let (_, second) = stall_put_after_free_word(&set, target);
            let first = group_mask(0);
            assert_eq!(second, group_mask(1));
            stripe.summary.fetch_or(first, Ordering::Release);
            let stale = stripe.summary.load(Ordering::Acquire);
            assert_eq!(stale, first);

            let competitor = {
                let set = Arc::clone(&set);
                thread::spawn(move || {
                    let summary = &set.stripes[0].summary;
                    let current = summary.fetch_or(second, Ordering::Release) | second;
                    let desired = (current & AVAILABILITY_MASK & !second) | encode_code(1);
                    assert_eq!(
                        summary.compare_exchange(
                            current,
                            desired,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ),
                        Ok(current)
                    );
                })
            };
            competitor.join().unwrap();

            let mut code_pending = 0;
            assert!(!Freelist::try_claim_cleanup(
                stripe,
                stale,
                0,
                first,
                &mut code_pending,
            ));
            assert_eq!(code_pending, second);

            let state = stripe.summary.load(Ordering::Acquire);
            assert_eq!(state & AVAILABILITY_MASK, first);
            assert_eq!(decode_code(state), Some(1));
            let mut claimed = None;
            let mut on_entry = |buffer| claimed = Some(buffer);
            let mut context = TakeContext {
                remaining: 1,
                on_entry: &mut on_entry,
            };
            set.scan_summarized_stripe_from_state(
                0,
                stripe,
                state,
                Probe::from_phase(0, 0),
                &mut context,
            );
            assert_eq!(context.remaining, 0);
            assert_eq!(claimed.as_ref().map(PooledBuffer::slot), Some(64));

            stripe
                .summary
                .fetch_and(AVAILABILITY_MASK, Ordering::Release);
            set.put(claimed.expect("the returned code names the live group"));
        });
    }

    /// Proves paired-group navigation reaches a partial final free word.
    #[test]
    fn summary_paired_group_reaches_partial_final_free_word() {
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

            set.put(target.expect("partial final free word slot"));
            let buffer = set
                .take()
                .expect("paired group must reach its tail free word");
            assert_eq!(buffer.slot(), 64);
            leases.push(buffer);
        });
    }

    /// Proves drain and put compose without drain mutating advisory navigation.
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

    /// Proves the first cursor claimant installs the phase inherited by followers.
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

    /// Small direct-mode ownership geometries for the broad Loom matrices.
    ///
    /// The variants cover one or multiple active words crossed with one or
    /// multiple active bits per word.
    #[allow(clippy::enum_variant_names)]
    #[derive(Clone, Copy, Debug)]
    enum Geometry {
        /// One active word containing one active bit.
        SingleWordSingleBit,
        /// One active word containing multiple active bits.
        SingleWordMultiBit,
        /// Multiple active words containing one active bit each.
        MultiWordSingleBit,
        /// Multiple active words containing multiple active bits.
        MultiWordMultiBit,
    }

    impl Geometry {
        /// Builds a freelist with this geometry's free-word shape.
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

        /// Returns the active slot ids, with no semantic ordering guarantee.
        const fn slots(self) -> &'static [u32] {
            match self {
                Self::SingleWordSingleBit => &[0],
                Self::SingleWordMultiBit => &[0, 1],
                Self::MultiWordSingleBit => &[0, 1, 2, 3],
                Self::MultiWordMultiBit => &[0, 2, 1, 3],
            }
        }

        /// Returns an active-slot mask for duplicate and completeness checks.
        fn slot_mask(self) -> usize {
            self.slots()
                .iter()
                .fold(0usize, |mask, &slot| mask | (1usize << slot))
        }
    }

    /// Complete direct-mode ownership geometry matrix.
    const ALL_GEOMETRIES: [Geometry; 4] = [
        Geometry::SingleWordSingleBit,
        Geometry::SingleWordMultiBit,
        Geometry::MultiWordSingleBit,
        Geometry::MultiWordMultiBit,
    ];

    /// Geometries with enough slots to exercise batch operations.
    const BATCH_GEOMETRIES: [Geometry; 3] = [
        Geometry::SingleWordMultiBit,
        Geometry::MultiWordSingleBit,
        Geometry::MultiWordMultiBit,
    ];

    /// Geometries whose active words span multiple stripes.
    const STRIPED_GEOMETRIES: [Geometry; 2] =
        [Geometry::MultiWordSingleBit, Geometry::MultiWordMultiBit];

    /// Geometries with multiple active bits in at least one word.
    const MULTI_BIT_GEOMETRIES: [Geometry; 2] =
        [Geometry::SingleWordMultiBit, Geometry::MultiWordMultiBit];

    /// Runs one cloned Loom model over each supplied direct-mode geometry.
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

    /// Owns buffers taken by a Loom model until they can be returned safely.
    ///
    /// This centralizes the test-side rule that every created buffer returns to
    /// the same freelist before that freelist is dropped.
    struct Leases {
        /// Freelist that owns every retained buffer.
        freelist: Arc<Freelist>,
        /// Buffers currently held outside the freelist by the model.
        buffers: Mutex<Vec<PooledBuffer>>,
    }

    impl Leases {
        /// Creates an empty external-owner collection.
        fn new(freelist: Arc<Freelist>) -> Arc<Self> {
            Arc::new(Self {
                freelist,
                buffers: Mutex::new(Vec::new()),
            })
        }

        /// Creates every buffer and returns them beside an empty lease owner.
        fn reserve(freelist: Arc<Freelist>) -> (Arc<Self>, Vec<PooledBuffer>) {
            let entries = Self::entries(&freelist);
            (Self::new(freelist), entries)
        }

        /// Lazily creates every buffer admitted by `freelist`.
        fn entries(freelist: &Freelist) -> Vec<PooledBuffer> {
            let mut entries = Vec::new();
            while let Some(entry) = freelist.try_create(false) {
                entries.push(entry);
            }
            entries
        }

        /// Retains one externally owned buffer for later return.
        fn push(&self, buffer: PooledBuffer) {
            self.buffers.lock().push(buffer);
        }

        /// Records a unique expected slot and retains its claimed buffer.
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
        /// Returns every retained buffer before releasing the owning freelist.
        fn drop(&mut self) {
            for buffer in self.buffers.lock().drain(..) {
                self.freelist.put(buffer);
            }
        }
    }

    /// Proves concurrent creation tickets never duplicate stable slots.
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

    /// Proves Release put publication transfers side-table writes to an Acquire take.
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

    /// Proves concurrent single puts merge disjoint bits in one free word.
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

    /// Proves concurrent batch puts merge disjoint masks in one free word.
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

    /// Proves single put and take RMWs compose on a partially free word.
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

    /// Proves put and batch take compose on a partially free word.
    #[test]
    fn put_and_take_batch_compose_on_partially_free_word() {
        // This is the batch-claim version of the partially-free word race:
        // `take_batch` may speculatively choose candidates from a stale Acquire
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

    /// Proves batch put and drain compose on a partially free word.
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

    /// Proves two takers cannot both claim one stale candidate bit.
    #[test]
    fn two_takers_cannot_claim_one_slot() {
        // Both takers may observe the same stale non-zero candidate word.
        // Only one may win the later `fetch_and` claim.
        //
        // This is the minimal stale-candidate case: the Acquire load may be
        // old, but the returned value from `fetch_and` must decide
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

    /// Proves a stale candidate can claim a later valid republication exactly once.
    #[test]
    fn stale_candidate_can_claim_republished_same_slot() {
        // An Acquire candidate load is not a reservation. One taker may observe
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

    /// Proves returned RMW state can help distinct new bits in one bounded scan.
    #[test]
    fn returned_state_helping_follows_distinct_bits_in_one_word_scan() {
        // The primary scan starts with D. The first claim returns D | A, so A
        // becomes its next candidate. While the D callback is paused, another
        // thread claims A and publishes C. The failed A claim returns C, which
        // the same `claim_word` invocation must then claim.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(3));
            let mut entries = Leases::entries(&freelist);
            entries.sort_unstable_by_key(PooledBuffer::slot);
            let d = entries.remove(0);
            let a = entries.remove(0);
            let c = entries.remove(0);
            let d_slot = d.slot();
            let a_slot = a.slot();
            let c_slot = c.slot();
            let d_mask = 1usize << d_slot;
            let c_mask = 1usize << c_slot;
            let expected = d_mask | c_mask;
            let leases = Leases::new(Arc::clone(&freelist));

            freelist.put(d);
            let candidates = freelist.stripes[0].free_word(0).load(Ordering::Acquire);
            assert_eq!(candidates, d_mask as u64);

            let (a_ready_tx, a_ready_rx) = mpsc::channel();
            let (d_claimed_tx, d_claimed_rx) = mpsc::channel();
            let (c_ready_tx, c_ready_rx) = mpsc::channel();
            let transition = {
                let freelist = Arc::clone(&freelist);
                let leases = Arc::clone(&leases);
                thread::spawn(move || {
                    freelist.put(a);
                    a_ready_tx.send(()).unwrap();
                    d_claimed_rx.recv().unwrap();
                    leases.push(claim_published_slot(&freelist, a_slot));
                    freelist.put(c);
                    c_ready_tx.send(()).unwrap();
                })
            };

            a_ready_rx.recv().unwrap();
            let seen = AtomicUsize::new(0);
            let mut first = true;
            let mut on_entry = |buffer: PooledBuffer| {
                let slot = buffer.slot();
                let mask = 1usize << slot;
                let previous = seen.fetch_or(mask, Ordering::Relaxed);
                assert_eq!(previous & mask, 0);
                leases.push(buffer);
                if first {
                    assert_eq!(slot, d_slot);
                    first = false;
                    d_claimed_tx.send(()).unwrap();
                    c_ready_rx.recv().unwrap();
                } else {
                    assert_eq!(slot, c_slot);
                }
            };
            let mut context = TakeContext {
                remaining: 2,
                on_entry: &mut on_entry,
            };
            freelist.claim_word(
                0,
                &freelist.stripes[0],
                0,
                candidates,
                Probe::from_phase(0, 0),
                &mut context,
            );

            transition.join().unwrap();
            assert_eq!(context.remaining, 0);
            assert_eq!(seen.load(Ordering::Relaxed), expected);
            assert_eq!(freelist.stripes[0].free_word(0).load(Ordering::Acquire), 0);
        });
    }

    /// Proves returned-state helping never retries a republished attempted bit.
    #[test]
    fn returned_state_helping_attempts_republished_bit_only_once() {
        // The primary scan starts with D and learns about A from its first RMW.
        // During the D callback, another thread claims A and republishes D. The
        // failed A claim returns D, but D is already in the attempted mask. The
        // scan must stop without claiming D a second time.
        loom::model(|| {
            let freelist = Arc::new(single_word_freelist(2));
            let mut entries = Leases::entries(&freelist);
            entries.sort_unstable_by_key(PooledBuffer::slot);
            let d = entries.remove(0);
            let a = entries.remove(0);
            let d_slot = d.slot();
            let a_slot = a.slot();
            let d_mask = 1u64 << d_slot;
            let leases = Leases::new(Arc::clone(&freelist));

            freelist.put(d);
            let candidates = freelist.stripes[0].free_word(0).load(Ordering::Acquire);
            assert_eq!(candidates, d_mask);

            let (a_ready_tx, a_ready_rx) = mpsc::channel();
            let (d_tx, d_rx) = mpsc::channel();
            let (d_ready_tx, d_ready_rx) = mpsc::channel();
            let transition = {
                let freelist = Arc::clone(&freelist);
                let leases = Arc::clone(&leases);
                thread::spawn(move || {
                    freelist.put(a);
                    a_ready_tx.send(()).unwrap();
                    let d = d_rx.recv().unwrap();
                    leases.push(claim_published_slot(&freelist, a_slot));
                    freelist.put(d);
                    d_ready_tx.send(()).unwrap();
                })
            };

            a_ready_rx.recv().unwrap();
            let callbacks = AtomicUsize::new(0);
            let mut on_entry = |buffer: PooledBuffer| {
                assert_eq!(buffer.slot(), d_slot);
                assert_eq!(callbacks.fetch_add(1, Ordering::Relaxed), 0);
                d_tx.send(buffer).unwrap();
                d_ready_rx.recv().unwrap();
            };
            let mut context = TakeContext {
                remaining: 2,
                on_entry: &mut on_entry,
            };
            freelist.claim_word(
                0,
                &freelist.stripes[0],
                0,
                candidates,
                Probe::from_phase(0, 0),
                &mut context,
            );

            transition.join().unwrap();
            assert_eq!(context.remaining, 1);
            assert_eq!(callbacks.load(Ordering::Relaxed), 1);
            assert_eq!(
                freelist.stripes[0].free_word(0).load(Ordering::Acquire),
                d_mask
            );
            leases.push(freelist.take().expect("republished D remains available"));
            assert!(freelist.take().is_none());
        });
    }

    /// Proves batch claims survive an intervening same-word RMW sequence.
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

    /// Proves single and batch takers cannot duplicate slot ownership.
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

    /// Proves concurrent batch takers cannot duplicate slot ownership.
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

    /// Proves a batch taker continues after losing its selected bits.
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

    /// Proves batch Release publication transfers ownership to batch Acquire claims.
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

    /// Proves a put publication transfers ownership to an Acquire drain.
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

    /// Proves batch publication transfers every returned slot to drain.
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

    /// Proves direct takes discover independent puts across all stripes.
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

    /// Proves drain and take partition free slots without duplication or loss.
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

    /// Proves concurrent drains partition free slots without duplication or loss.
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

    /// Proves drain and batch take partition slots without duplication or loss.
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
