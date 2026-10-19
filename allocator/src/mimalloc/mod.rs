//! [mimalloc](https://github.com/microsoft/mimalloc) is a general-purpose
//! allocator that serves each size class from thread-local pages carved out
//! of arenas of operating system memory, returns an object freed by any
//! thread to the page it came from, and purges freed arena memory back to
//! the operating system after a delay.
//!
//! This module installs mimalloc as the global allocator through
//! [`MiMalloc`], a [`GlobalAlloc`] whose [`Config`] lives in the binary and
//! is applied by the first allocation. It reports on the allocator through
//! [`Effective`] and [`Stats`].
//!
//! # Configuration timing
//!
//! mimalloc parses its environment options when it is loaded and consults
//! them as it runs. It creates its first arena at the first allocation, which
//! happens before `main` on most targets. An option set from `main`
//! therefore takes effect late. A reservation made from `main` becomes a
//! second arena, and threads search it only after the automatic one.
//!
//! [`MiMalloc`] applies its [`Config`] on the first allocation it serves. The
//! purge policy is then in force before any memory is freed. A reservation is
//! the first arena unless the environment requested one of its own with
//! `MIMALLOC_RESERVE_OS_MEMORY` or `MIMALLOC_RESERVE_HUGE_OS_PAGES`. mimalloc
//! honors those variables when it is loaded.
//!
//! # Page geometry
//!
//! mimalloc carves arenas into slices and derives its page sizes from the
//! slice. Slices form chunks, and chunks form the metadata groups of an
//! arena. One group looks like this with the default slice on 64-bit targets:
//!
//! ```text
//! one metadata group: 8 chunks, 256 MiB
//!         |<----- ARENA_MAX_OBJECT_SIZE: 7 chunks, 224 MiB ------>|
//! +-------+-------+-------+-------+-------+---------------+-------+
//! |chunk 0|chunk 1|chunk 2|chunk 3|chunk 4|page of its own|chunk 7|
//! +-------+-------+-------+-------+-------+---------------+-------+
//! |       |
//! |       '-------------------------------------------------------.
//! |                                                               |
//! +--------+--------+---------+-----------------+-----------------+
//! |  page  | small  | medium  |      large      |                 |
//! |metadata|1 slice |8 slices |    64 slices    |       ...       |
//! |  table | 64 KiB | 512 KiB |      4 MiB      |                 |
//! +--------+--------+---------+-----------------+-----------------+
//!          |<------>| ARENA_SLICE_SIZE
//! |<----------- ARENA_CHUNK_SIZE: 512 slices, 32 MiB ------------>|
//! ```
//!
//! Objects up to [`LARGE_OBJECT_LIMIT`] are served from thread-local pages at
//! the cost of a free-list operation. Larger objects get a page of their own,
//! which takes an arena operation per allocation and free. That costs
//! hundreds of nanoseconds, and microseconds when many threads allocate at
//! once.
//!
//! The limit is a build-time choice made with the crate's `large-objects-*`
//! features, which scale the slice ([`ARENA_SLICE_SIZE`]) and with it every
//! page size. Only a binary should enable them. The geometry is a property
//! of the whole process, and Cargo unifies the largest limit requested in a
//! build.
//!
//! # Large objects
//!
//! Where an allocation lives depends on its size and alignment:
//!
//! ```text
//! allocation (size, alignment)
//!   |
//!   +-- alignment >= metadata group (256 MiB) ---> null
//!   |
//!   +-- alignment > ARENA_SLICE_SIZE (64 KiB) ---> page of its own,
//!   |                                              mapped from the OS
//!   v
//! size <= LARGE_OBJECT_LIMIT (512 KiB)?
//!   | yes                             | no
//!   v                                 v
//! shared page of its size class       page of its own
//!   |                                 |
//!   '----------------+----------------'
//!                    v
//! page <= Config::arena_max_object_size?
//!   | yes                             | no
//!   v                                 v
//! arena -- no room, no new arena ---> OS mapping
//! ```
//!
//! Objects up to [`LARGE_OBJECT_LIMIT`] share a thread-local page with others
//! of their size class, and the page outlives them for reuse. Larger objects
//! get a page of their own, sized to the object rounded up (by as much as
//! 4 MiB for the largest). Freeing the object releases the page. One case
//! keeps its page longer. A small object aligned beyond a slice and freed by
//! another thread holds its page until the owning thread collects.
//!
//! An arena keeps a released page and purges it on the [`Purge`] schedule.
//! A page spanning several chunks (see [`ARENA_CHUNK_SIZE`]) needs as many
//! consecutive chunks that are entirely free. A fragmented arena can
//! therefore make mimalloc reserve a new arena for the page or, failing that,
//! map the page from the operating system. A page mapped from the operating
//! system is unmapped on release. Each such allocation costs system calls and
//! fresh page faults, and nothing is retained.
//!
//! [`Config::arena_max_object_size`] is at most [`ARENA_MAX_OBJECT_SIZE`], the
//! largest page an arena can hold, and defaults to it. mimalloc's own ceiling
//! is slightly higher and admits pages no arena can place. For each such page
//! it reserves an arena it cannot use before falling back to the operating
//! system. [`MiMalloc`] therefore caps the limit whatever its source. Lowering
//! the limit below the largest shared page moves shared pages of the larger
//! size classes to the operating system as well. How long they are kept does
//! not change.
//!
//! Alignments of a whole metadata group or more are refused. A group spans as
//! many chunks as a word has bytes. The request returns null, which a
//! [`GlobalAlloc`] caller reports as an allocation error.
//!
//! # Example
//!
//! ```no_run
//! use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve};
//! use std::time::Duration;
//!
//! #[global_allocator]
//! static GLOBAL: MiMalloc = MiMalloc::new(Config {
//!     purge: Purge::After(Duration::from_secs(10)),
//!     reserve: Some(Reserve::pinned(2 << 30)),
//!     ..Config::DEFAULT
//! });
//!
//! fn main() {
//!     assert!(commonware_allocator::mimalloc::is_global_allocator());
//!     println!("{:?}", GLOBAL.status());
//! }
//! ```

mod ffi;

use ffi as mi;
use std::{
    alloc::{GlobalAlloc, Layout},
    ffi::{CStr, c_long, c_void},
    hint::spin_loop,
    ptr,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    time::Duration,
};

/// Runtime options the wrapper reads or writes, with their `mi_option_t`
/// values from the vendored `mimalloc.h`. A test derives the values from
/// that header, so an upgrade that renumbers the enum fails there instead of
/// configuring the wrong option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
enum OptionId {
    /// Commit policy for arenas mimalloc reserves on demand: 0 on first use,
    /// 1 eagerly, 2 eagerly where the system overcommits or large OS pages
    /// are allowed.
    ArenaEagerCommit = 4,
    /// Whether a purge decommits memory rather than resetting it (flag).
    PurgeDecommits = 5,
    /// Whether arenas may be backed by large OS pages (flag).
    AllowLargeOsPages = 6,
    /// Milliseconds a freed arena range waits before it may be purged: -1
    /// never purges, 0 purges on free.
    PurgeDelay = 15,
    /// Base size of arenas reserved on demand, in KiB.
    ArenaReserve = 23,
    /// Factor applied to the purge delay for arena memory.
    ArenaPurgeMult = 24,
    /// Transparent huge pages: 0 disallowed, 1 allowed, 2 allowed with
    /// purging in whole huge pages.
    AllowThp = 43,
    /// Largest page an arena may hold, in KiB.
    ArenaMaxObjectSize = 45,
}

impl OptionId {
    fn get(self) -> c_long {
        mi::mi_option_get(self as mi::mi_option_t)
    }

    fn set(self, value: c_long) {
        // SAFETY: callers pass flags, sizes in KiB that fit `c_long` once
        // multiplied back, or a purge delay bounded by `MAX_PURGE_DELAY`, and
        // every caller runs inside `apply`, under the `OptionsGuard` that
        // `configure` holds, so no public reader observes the plain option
        // fields mid-write.
        unsafe { mi::mi_option_set(self as mi::mi_option_t, value) }
    }
}

/// Bytes handed to mimalloc as pinned arenas by this process. mimalloc's own
/// accounting covers only memory it mapped itself, so pinned reservations
/// are reported separately in [`Stats::pinned_bytes`].
static PINNED_BYTES: AtomicU64 = AtomicU64::new(0);

// Option fields in the linked allocator are plain C values. Configuration
// writes them and `Effective::read` and `collect` read them, so all three hold
// this guard and cannot race. mimalloc's own reads of them happen inside
// allocations, which wait for the state published after configuration. The
// guard itself never allocates because configuration runs inside alloc.
static OPTIONS_LOCK: AtomicBool = AtomicBool::new(false);

struct OptionsGuard;

impl OptionsGuard {
    fn lock() -> Self {
        while OPTIONS_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        Self
    }
}

impl Drop for OptionsGuard {
    fn drop(&mut self) {
        OPTIONS_LOCK.store(false, Ordering::Release);
    }
}

/// Log2 of the arena slice size selected by the `large-objects-*` features;
/// the default is mimalloc's (`13 + MI_SIZE_SHIFT` in the vendored
/// `types.h`).
const ARENA_SLICE_SHIFT: u32 = if cfg!(feature = "large-objects-4m") {
    19
} else if cfg!(feature = "large-objects-2m") {
    18
} else if cfg!(feature = "large-objects-1m") {
    17
} else {
    13 + size_of::<usize>().trailing_zeros()
};

/// Size of an arena slice, the unit mimalloc carves arenas into and the
/// smallest page size. A test checks it against the vendored build.
pub const ARENA_SLICE_SIZE: usize = 1 << ARENA_SLICE_SHIFT;

/// Size of an arena chunk, the unit reservations are rounded to
/// ([`Reserve::bytes`]): 512 slices, so 32 MiB at the default slice.
pub const ARENA_CHUNK_SIZE: usize = 64 * size_of::<usize>() * ARENA_SLICE_SIZE;

/// Largest allocation served from a thread-local page: eight slices, so
/// 512 KiB by default and the size named by an enabled `large-objects-*`
/// feature. Larger objects get a page of their own, which costs an arena
/// operation per allocation and free.
pub const LARGE_OBJECT_LIMIT: usize = size_of::<usize>() * ARENA_SLICE_SIZE;

/// Largest page an arena can hold, and so the most
/// [`Config::arena_max_object_size`] admits: one chunk short of a metadata
/// group, so seven chunks (224 MiB at the default slice) on 64-bit targets.
/// mimalloc keeps page metadata in the first slices of every group of chunks,
/// as many chunks as a word has bytes, and places a page spanning several
/// chunks only in that many consecutive chunks that are entirely free, so no
/// page can span a whole group. A test checks that the vendored build places
/// a page of this size in an arena.
pub const ARENA_MAX_OBJECT_SIZE: usize = (size_of::<usize>() - 1) * ARENA_CHUNK_SIZE;

/// When memory freed back to an arena is purged (decommitted) to the
/// operating system.
///
/// Purging is deadline based and runs during mimalloc's collection passes
/// (see [`Purge::After`]). It covers arena memory, which backs every
/// allocation except pages above [`Config::arena_max_object_size`] and
/// objects aligned beyond a slice; those are mapped directly and unmapped on
/// release whatever the policy. Memory in a pinned reservation (see
/// [`Reserve`]) is never purged.
///
/// With transparent huge pages allowed on a kernel that supports them (the
/// default, and what [`Config::transparent_huge_pages`] selects), a pass
/// purges only the 2 MiB-aligned granules whose slices have all been freed
/// since the arena's last pass, so a freed range smaller than 2 MiB, or the
/// partial granules at the ends of a larger one, stays resident until its
/// neighbors are freed as well, even under a forced [`collect`]. The
/// environment can select a finer granule
/// (`MIMALLOC_ALLOW_THP=1` or `MIMALLOC_MINIMAL_PURGE_SIZE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purge {
    /// Keep mimalloc's default: its purge delay times its arena multiplier
    /// (four seconds in mimalloc 3.5).
    Default,
    /// Never purge arena memory.
    Never,
    /// Purge freed memory after a delay: the first free into an arena after a
    /// purge arms a deadline this far ahead, later frees into that arena
    /// share it, and once it has passed a collection pass purges the arena's
    /// freed memory together. mimalloc runs such passes only when a thread
    /// collects (every 10,000 allocations that miss its fast path by default,
    /// or [`collect`]), and an unforced pass purges a few arenas at a time,
    /// so memory freed early in an arena's cycle stays resident for at least
    /// this long, memory freed just before the deadline may go with it, and a
    /// process that allocates rarely keeps everything until its next pass.
    /// Delays above [`MAX_PURGE_DELAY`] are clamped to it, and a delay below
    /// one millisecond purges each page as it is freed into the arena.
    After(Duration),
}

/// Longest purge delay [`Purge::After`] applies (about 24 days): mimalloc
/// stores the delay in milliseconds in a C `long`, so the bound keeps the
/// option in range on every platform.
pub const MAX_PURGE_DELAY: Duration = Duration::from_millis(i32::MAX as u64);

/// Memory reserved from the operating system before the first allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reserve {
    /// Bytes to reserve. mimalloc manages arenas in chunks of
    /// [`ARENA_CHUNK_SIZE`], so the amount is rounded down to whole chunks and
    /// reservations below one chunk fail.
    pub bytes: usize,
    /// Pinned memory is mapped by this crate and handed to mimalloc as an
    /// arena that is never purged, whatever the [`Purge`] policy. It needs no
    /// large OS page configuration. Unpinned memory is reserved through
    /// mimalloc and purged like any other arena unless the kernel granted it
    /// large OS pages (see [`Config::allow_large_os_pages`]). On Linux both
    /// are advised to use transparent huge pages when
    /// [`Config::transparent_huge_pages`] allows them, as mimalloc's own
    /// arenas are.
    pub pinned: bool,
    /// Touch every page of a pinned reservation up front so first use never
    /// faults. Ignored for unpinned reservations.
    pub prefault: bool,
}

impl Reserve {
    /// A pinned reservation that is faulted in on first use.
    pub const fn pinned(bytes: usize) -> Self {
        Self {
            bytes,
            pinned: true,
            prefault: false,
        }
    }

    /// A reservation managed and purged by mimalloc.
    pub const fn unpinned(bytes: usize) -> Self {
        Self {
            bytes,
            pinned: false,
            prefault: false,
        }
    }
}

/// Configuration applied by [`MiMalloc`] on its first allocation.
///
/// Every field has a "leave mimalloc's default" value, so
/// [`Config::DEFAULT`] changes nothing but the cap on the arena object-size
/// limit (see [`Config::arena_max_object_size`]) and environment variables
/// keep working.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// When freed memory is purged back to the operating system.
    pub purge: Purge,
    /// Memory reserved before the first allocation.
    pub reserve: Option<Reserve>,
    /// Whether mimalloc may back arenas with large (2 MiB) OS pages when the
    /// kernel grants them (`None` keeps mimalloc's default, which the
    /// environment may have enabled). Large-page arenas are never purged;
    /// the pages are not swappable and come out of the kernel's huge-page
    /// pool.
    pub allow_large_os_pages: Option<bool>,
    /// Whether the process may use transparent huge pages (`None` keeps the
    /// current state: allowed unless the environment disabled them). On
    /// Linux this sets the process flag the kernel consults for every
    /// mapping; elsewhere it only informs mimalloc. Huge pages cut page
    /// faults and TLB misses for large buffers but can raise resident memory
    /// for processes dominated by small objects, and purging then works in
    /// whole 2 MiB granules (see [`Purge`]). An environment that disabled
    /// huge pages before load (`MIMALLOC_ALLOW_THP=0`) is remembered by
    /// mimalloc: `Some(true)` then restores the process flag but mimalloc
    /// still does not advise huge pages for its own mappings.
    pub transparent_huge_pages: Option<bool>,
    /// Whether the arenas mimalloc reserves on its own are committed eagerly
    /// rather than on first use. `None` keeps mimalloc's default (eager on
    /// systems that overcommit or when large OS pages are allowed).
    pub arena_eager_commit: Option<bool>,
    /// Base size of the arenas mimalloc reserves on demand once existing
    /// arenas are full, rounded up to KiB and raised to at least one
    /// [`ARENA_CHUNK_SIZE`] (two in practice, as mimalloc adds a chunk of
    /// headroom for metadata); mimalloc grows it with the arena count and
    /// for a request that needs more. `None` keeps mimalloc's default
    /// (1 GiB).
    /// `Some(0)` stops mimalloc from reserving arenas at all: pages that no
    /// existing arena can hold are then mapped from the operating system one
    /// at a time and unmapped on release.
    pub arena_reserve: Option<usize>,
    /// Largest page carved from an arena, in bytes, rounded up to a slice and
    /// kept between one slice and [`ARENA_MAX_OBJECT_SIZE`] (see the module
    /// docs on large objects). Pages above it are mapped directly from the
    /// operating system and unmapped on release, whatever the [`Purge`]
    /// policy, so lowering the limit keeps occasional huge buffers from
    /// holding arena memory; below the largest shared page (64 slices) it
    /// moves shared pages too, which are kept for reuse regardless. `None`
    /// keeps mimalloc's default or the environment's value, under the same
    /// cap.
    pub arena_max_object_size: Option<usize>,
}

impl Config {
    /// Leaves every mimalloc option at its default, capping only the arena
    /// object-size limit at [`ARENA_MAX_OBJECT_SIZE`].
    pub const DEFAULT: Self = Self {
        purge: Purge::Default,
        reserve: None,
        allow_large_os_pages: None,
        transparent_huge_pages: None,
        arena_eager_commit: None,
        arena_reserve: None,
        arena_max_object_size: None,
    };
}

impl Default for Config {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Outcome of the reservation requested by [`Config::reserve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// No reservation was requested.
    NotRequested,
    /// The reservation is a pinned arena that is never purged.
    Pinned,
    /// The reservation is an ordinary arena managed by mimalloc.
    Reserved,
    /// The operating system or mimalloc refused the reservation; allocation
    /// continues from automatically reserved arenas.
    Failed,
}

/// What the process's [`MiMalloc`] has done so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// Whether a configuration has been applied to the process (the first
    /// allocation served by a [`MiMalloc`] applies it, so this is false only
    /// before any such allocation happened).
    pub configured: bool,
    /// Outcome of the requested reservation.
    pub reserve: ReserveOutcome,
}

/// Largest alignment `mi_malloc` can satisfy without the aligned entry points
/// (`MI_MAX_ALIGN_SIZE` in the vendored `mimalloc/types.h`). Every block is
/// word aligned: size classes are word multiples and pages start their
/// blocks word aligned. Size classes that are multiples of 16 start their
/// blocks 16-byte aligned as well, and every size that is a multiple of 16
/// maps to such a class, so those layouts skip the aligned entry points and
/// their validity check and small-block alignment probe. A test checks the
/// constant against the header.
const MALLOC_ALIGNMENT: usize = 16;

/// Alignment every `mi_malloc` block has regardless of size.
const WORD_ALIGNMENT: usize = size_of::<usize>();

/// Whether plain `mi_malloc` satisfies `align` for a block of `size` bytes. A
/// layout's alignment is a power of two, so the size check is a mask rather
/// than a division.
#[inline]
const fn malloc_satisfies(size: usize, align: usize) -> bool {
    align <= WORD_ALIGNMENT || (align <= MALLOC_ALIGNMENT && size & (align - 1) == 0)
}

/// Zero until a [`MiMalloc`] has applied its configuration, then the
/// [`ReserveOutcome`] plus one, published by a release store once `apply` has
/// returned. The option table is process-wide, so this state is too: the
/// first instance to serve an allocation configures the process, and the
/// configuration of any other instance is never applied.
static STATE: AtomicU8 = AtomicU8::new(0);

/// mimalloc as a `#[global_allocator]` with a [`Config`] applied on the first
/// allocation.
///
/// Construction is `const`, so a configured allocator can be a `static`
/// directly. Applying the configuration performs no Rust allocation, so the
/// first allocation cannot recurse into the allocator. The configuration is
/// process-wide, like the statistics in [`Effective`] and [`Stats`]: the
/// first instance to serve an allocation applies its [`Config`], and the
/// configuration of any other instance is never applied.
pub struct MiMalloc {
    config: Config,
}

impl MiMalloc {
    /// Creates an allocator that applies `config` on its first allocation.
    pub const fn new(config: Config) -> Self {
        Self { config }
    }

    /// Returns the configuration this allocator applies.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Reports whether the process has been configured and how the
    /// reservation went.
    pub fn status(&self) -> Status {
        let Some(outcome) = STATE.load(Ordering::Acquire).checked_sub(1) else {
            return Status {
                configured: false,
                reserve: ReserveOutcome::NotRequested,
            };
        };
        let reserve = match outcome {
            x if x == ReserveOutcome::Pinned as u8 => ReserveOutcome::Pinned,
            x if x == ReserveOutcome::Reserved as u8 => ReserveOutcome::Reserved,
            x if x == ReserveOutcome::Failed as u8 => ReserveOutcome::Failed,
            _ => ReserveOutcome::NotRequested,
        };
        Status {
            configured: true,
            reserve,
        }
    }

    #[inline]
    fn ensure_configured(&self) {
        if STATE.load(Ordering::Acquire) == 0 {
            self.configure();
        }
    }

    /// Applies the configuration exactly once. Concurrent first allocations
    /// wait on the options guard for the configuring thread and then find
    /// the state set. Nothing here allocates through Rust.
    #[cold]
    #[inline(never)]
    fn configure(&self) {
        let _guard = OptionsGuard::lock();
        if STATE.load(Ordering::Relaxed) != 0 {
            return;
        }
        let outcome = apply(&self.config);
        STATE.store(outcome as u8 + 1, Ordering::Release);
    }
}

// SAFETY: mimalloc is thread-safe and the configuration state is only touched
// through atomics. Every entry point returns memory aligned for its layout:
// `malloc_satisfies` admits only the layouts plain `mi_malloc` aligns, the
// rest take the aligned entry points, and mimalloc frees and reallocates
// blocks from either.
unsafe impl GlobalAlloc for MiMalloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.ensure_configured();
        if malloc_satisfies(layout.size(), layout.align()) {
            mi::mi_malloc(layout.size()) as *mut u8
        } else {
            mi::mi_malloc_aligned(layout.size(), layout.align()) as *mut u8
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.ensure_configured();
        if malloc_satisfies(layout.size(), layout.align()) {
            mi::mi_zalloc(layout.size()) as *mut u8
        } else {
            mi::mi_zalloc_aligned(layout.size(), layout.align()) as *mut u8
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // SAFETY: GlobalAlloc requires ptr to come from this allocator.
        unsafe { mi::mi_free(ptr as *mut c_void) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // The block `mi_realloc` returns is aligned for the layout whenever
        // the new size satisfies it: in place it is the block allocated for
        // `layout`, and after a move it is a fresh plain block of `new_size`
        // bytes, in its exact size class. The aligned entry point can pad a
        // moved block by up to the alignment, which moves a request that
        // exactly fills a size class into the next one.
        // SAFETY: GlobalAlloc requires ptr to come from this allocator with the given layout.
        unsafe {
            if malloc_satisfies(new_size, layout.align()) {
                mi::mi_realloc(ptr as *mut c_void, new_size) as *mut u8
            } else {
                mi::mi_realloc_aligned(ptr as *mut c_void, new_size, layout.align()) as *mut u8
            }
        }
    }
}

/// Applies `config` to the process-wide mimalloc instance. The caller holds
/// the [`OptionsGuard`].
fn apply(config: &Config) -> ReserveOutcome {
    mi::mi_process_init();
    match config.purge {
        Purge::Default => {}
        Purge::Never => OptionId::PurgeDelay.set(-1),
        Purge::After(delay) => {
            // mimalloc scales the delay by its arena multiplier, and arenas
            // are the only purge path in version 3, so a multiplier of one
            // makes the configured delay the effective one.
            OptionId::PurgeDelay.set(purge_millis(delay));
            OptionId::ArenaPurgeMult.set(1);
        }
    }
    if let Some(eager) = config.arena_eager_commit {
        OptionId::ArenaEagerCommit.set(c_long::from(eager));
    }
    if let Some(allowed) = config.allow_large_os_pages {
        OptionId::AllowLargeOsPages.set(c_long::from(allowed));
    }
    if let Some(allowed) = config.transparent_huge_pages {
        set_transparent_huge_pages(allowed);
    }
    if let Some(bytes) = config.arena_reserve {
        OptionId::ArenaReserve.set(size_option(bytes.div_ceil(1024)));
    }

    // mimalloc's own ceiling on the limit admits pages no arena can hold and
    // reserves a futile arena for each before falling back to the operating
    // system, so the limit is capped at `ARENA_MAX_OBJECT_SIZE` whatever its
    // source.
    let limit = config.arena_max_object_size.map_or_else(
        || OptionId::ArenaMaxObjectSize.get(),
        |bytes| size_option(bytes.div_ceil(1024)),
    );
    OptionId::ArenaMaxObjectSize.set(limit.min(size_option(ARENA_MAX_OBJECT_SIZE / 1024)));
    match config.reserve {
        None => ReserveOutcome::NotRequested,
        Some(reserve) => {
            let Some(size) = whole_chunks(reserve.bytes) else {
                return ReserveOutcome::Failed;
            };
            if reserve.pinned {
                return manage_pinned(size, reserve.prefault);
            }

            // Large pages are permitted as for the arenas mimalloc reserves
            // on its own: its mapping code consults `allow_large_os_pages`
            // before trying them, and the permission also lets the mapping
            // receive the transparent huge page advice such arenas get.
            // SAFETY: the arena identifier output is null, so nothing is
            // written through it.
            let err =
                unsafe { mi::mi_reserve_os_memory_ex(size, true, true, false, ptr::null_mut()) };
            if err == 0 {
                ReserveOutcome::Reserved
            } else {
                ReserveOutcome::Failed
            }
        }
    }
}

/// The whole arena chunks a reservation of `bytes` provides, or `None` below
/// one chunk. mimalloc uses a reservation in whole chunks, so trimming the
/// request keeps the remainder from being mapped at all.
fn whole_chunks(bytes: usize) -> Option<usize> {
    let chunk = mi::mi_arena_min_size();
    Some(bytes / chunk * chunk).filter(|size| *size > 0)
}

/// A size option in the KiB mimalloc stores, bounded so the value it reads
/// back in bytes fits the option type.
fn size_option(kib: usize) -> c_long {
    kib.min(c_long::MAX as usize / 1024) as c_long
}

/// A purge delay in the milliseconds mimalloc stores, bounded by
/// [`MAX_PURGE_DELAY`].
fn purge_millis(delay: Duration) -> c_long {
    delay.min(MAX_PURGE_DELAY).as_millis() as c_long
}

/// The delay after which mimalloc purges unused arena memory, computed from
/// the raw options the way its arena code does: a negative factor disables
/// purging, and a product that does not fit falls back to the bare delay.
fn arena_purge_delay(delay: c_long, mult: c_long) -> Option<Duration> {
    if delay < 0 || mult < 0 {
        return None;
    }
    let (delay, mult) = (delay as u64, mult as u64);
    let total = delay
        .checked_mul(mult)
        .filter(|total| c_long::try_from(*total).is_ok())
        .unwrap_or(delay);
    Some(Duration::from_millis(total))
}

/// Applies the transparent huge page policy.
///
/// mimalloc reads this option when it initializes at load time. A later
/// value still steers its madvise calls for new mappings and its purge
/// granularity, but the process-wide flag that disables transparent huge pages
/// on Linux is only touched during that initialization, so the wrapper
/// maintains the flag itself, in both directions.
fn set_transparent_huge_pages(allowed: bool) {
    // mimalloc's default (2) allows huge pages and purges at huge-page
    // granularity so purging does not split them.
    OptionId::AllowThp.set(if allowed { 2 } else { 0 });
    #[cfg(target_os = "linux")]
    // SAFETY: this prctl takes integer arguments only.
    unsafe {
        libc::prctl(
            libc::PR_SET_THP_DISABLE,
            libc::c_ulong::from(!allowed),
            0,
            0,
            0,
        );
    }
}

/// Maps `size` bytes of anonymous memory, a whole number of chunks, and
/// hands them to mimalloc as a pinned, committed arena.
///
/// mimalloc needs an arena aligned to its minimum arena alignment, so the
/// memory is mapped with alignment slack and trimmed on both ends before the
/// handover. Only the retained range is prefaulted and counted in
/// [`Stats::pinned_bytes`].
fn manage_pinned(size: usize, prefault: bool) -> ReserveOutcome {
    let alignment = mi::mi_arena_min_alignment();
    let Some(len) = size.checked_add(alignment) else {
        return ReserveOutcome::Failed;
    };
    // SAFETY: anonymous mapping with no file descriptor.
    let base = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return ReserveOutcome::Failed;
    }
    let Some(start) = (base as usize).checked_next_multiple_of(alignment) else {
        // SAFETY: the mapping was created above and never handed out.
        unsafe { libc::munmap(base, len) };
        return ReserveOutcome::Failed;
    };
    let head = start - base as usize;
    let tail = len - head - size;
    // SAFETY: both slack ranges lie inside the mapping created above and are
    // never handed to mimalloc.
    unsafe {
        if head > 0 {
            libc::munmap(base, head);
        }
        if tail > 0 {
            libc::munmap((start + size) as *mut c_void, tail);
        }
    }

    // mimalloc advises huge pages for the arenas it maps itself whenever they
    // are allowed; the pinned reservation gets the same advice so a kernel in
    // madvise mode backs it with huge pages too.
    #[cfg(target_os = "linux")]
    if OptionId::AllowThp.get() != 0 {
        // SAFETY: the range is a live private mapping owned by this function.
        unsafe { libc::madvise(start as *mut c_void, size, libc::MADV_HUGEPAGE) };
    }
    if prefault {
        // SAFETY: every touched address lies inside the retained range.
        unsafe {
            let page = libc::sysconf(libc::_SC_PAGESIZE).max(4096) as usize;
            let mut offset = 0;
            while offset < size {
                ptr::write_volatile((start + offset) as *mut u8, 0);
                offset += page;
            }
        }
    }

    // SAFETY: the range is a live private mapping that nothing else uses;
    // mimalloc takes it over for the rest of the process.
    let managed = unsafe {
        mi::mi_manage_os_memory_ex(
            start as *mut c_void,
            size,
            true,
            true,
            true,
            -1,
            false,
            ptr::null_mut(),
        )
    };
    if managed {
        PINNED_BYTES.fetch_add(size as u64, Ordering::Relaxed);
        ReserveOutcome::Pinned
    } else {
        // SAFETY: the aligned remainder of the mapping was never handed out.
        unsafe { libc::munmap(start as *mut c_void, size) };
        ReserveOutcome::Failed
    }
}

/// Returns whether the process's global allocator is the mimalloc linked by
/// this crate, installed through [`MiMalloc`] directly or wrapped by another
/// allocator.
///
/// A fresh allocation is checked against that instance's heap region.
pub fn is_global_allocator() -> bool {
    let probe = Box::new(0u8);
    mi::mi_is_in_heap_region(ptr::from_ref::<u8>(&probe).cast())
}

/// Returns the linked mimalloc version as `major * 10000 + minor * 100 + patch`.
pub fn version() -> u32 {
    mi::mi_version() as u32
}

/// Returns the size mimalloc allocates for a request of `size` bytes: its
/// size class, or, above the largest class, the request rounded up to an OS
/// page. The page that serves such a request may be rounded further.
pub fn good_size(size: usize) -> usize {
    mi::mi_good_size(size)
}

/// Collects freed memory now: returns completed pages to the arenas, purges
/// arena memory whose purge deadline has passed, and, when `force` is set,
/// purges the rest without waiting for the purge delay, within the huge
/// page granularity described on [`Purge`]. Nothing is purged under
/// [`Purge::Never`], and pinned reservations are never purged.
/// Only the calling thread's allocation counters are merged into [`Stats`]
/// by this.
pub fn collect(force: bool) {
    let _guard = OptionsGuard::lock();
    mi::mi_collect(force);
}

/// The options mimalloc is running with, whether set by a [`Config`], the
/// environment, or its defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effective {
    /// Purge policy: `None` never purges, otherwise the delay after which
    /// unused arena memory becomes eligible for purging at the next
    /// collection pass (mimalloc's purge delay times its arena multiplier).
    pub purge: Option<Duration>,
    /// Whether a purge decommits memory rather than resetting it.
    pub purge_decommits: bool,
    /// Arena commit policy as mimalloc stores it (0 lazy, 1 eager, 2 eager on
    /// systems that overcommit or when large OS pages are allowed).
    pub arena_eager_commit: i64,
    /// Whether arenas may use large OS pages.
    pub allow_large_os_pages: bool,
    /// Whether mimalloc may use transparent huge pages.
    pub transparent_huge_pages: bool,
    /// Base size of arenas reserved on demand, before mimalloc grows it with
    /// the arena count.
    pub arena_reserve: usize,
    /// Largest page carved from an arena: the configured limit rounded up to
    /// a slice and kept between one slice and [`ARENA_MAX_OBJECT_SIZE`].
    pub arena_max_object_size: usize,
}

impl Effective {
    /// Reads the current option values.
    pub fn read() -> Self {
        let _guard = OptionsGuard::lock();

        // `c_long` is 32 bits on some platforms, so the cast is not always a
        // no-op.
        #[allow(clippy::unnecessary_cast)]
        let arena_eager_commit = OptionId::ArenaEagerCommit.get() as i64;
        Self {
            purge: arena_purge_delay(OptionId::PurgeDelay.get(), OptionId::ArenaPurgeMult.get()),
            purge_decommits: OptionId::PurgeDecommits.get() != 0,
            arena_eager_commit,
            allow_large_os_pages: OptionId::AllowLargeOsPages.get() != 0,
            transparent_huge_pages: OptionId::AllowThp.get() != 0,
            arena_reserve: usize::try_from(OptionId::ArenaReserve.get())
                .unwrap_or(0)
                .saturating_mul(1024),
            arena_max_object_size: mi::mi_arena_max_object_size(),
        }
    }
}

/// Process-wide allocator statistics.
///
/// Memory accounting against the operating system (reservations, commits,
/// purges, mappings, arenas, threads) and the process figures are current
/// when read. Allocation counters ([`Self::allocated_bytes`],
/// [`Self::allocated_peak_bytes`], [`Self::pages`],
/// [`Self::huge_allocations`], [`Self::huge_bytes`]) are kept per thread and
/// folded into the process totals when that thread collects (which mimalloc
/// does every 10,000 allocations that miss its fast path), reads statistics
/// itself, or exits, so they reflect each thread's last merge rather than
/// its live state. Per-size-class counts are not included.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Bytes mimalloc has mapped from the operating system: its arenas, its
    /// page map, and the pages it maps directly.
    ///
    /// Pinned reservations handed over by this crate are counted in
    /// [`Self::pinned_bytes`] instead.
    pub reserved_bytes: u64,
    /// Bytes of pinned reservations handed to mimalloc by this crate; this
    /// memory is never purged.
    pub pinned_bytes: u64,
    /// Bytes currently committed, as mimalloc accounts them: on systems that
    /// overcommit, an arena mimalloc reserves on demand and commits eagerly
    /// counts as its slices are first used, while an unpinned [`Reserve`]
    /// counts in full at once and again as its slices are first used. A
    /// purge does not lower the figure on Unix, where decommitted memory
    /// keeps its mapping.
    pub committed_bytes: u64,
    /// Peak committed bytes.
    pub committed_peak_bytes: u64,
    /// Bytes currently handed out to callers, as the allocator accounts them
    /// (block sizes, so including size-class rounding).
    pub allocated_bytes: u64,
    /// Peak bytes handed out, as the sum of the separately tracked normal
    /// and huge-object peaks, so it can exceed the peak of their sum.
    pub allocated_peak_bytes: u64,
    /// Cumulative bytes purged back to the operating system.
    pub purged_bytes: u64,
    /// Cumulative purge operations.
    pub purge_calls: u64,
    /// Cumulative arena-level purge passes.
    pub arena_purges: u64,
    /// Cumulative memory mappings requested from the operating system.
    pub mmap_calls: u64,
    /// Cumulative commit operations.
    pub commit_calls: u64,
    /// Pages (mimalloc's unit of size-class storage) currently in use.
    pub pages: u64,
    /// Threads currently known to the allocator.
    pub threads: u64,
    /// Arenas currently managed.
    pub arenas: u64,
    /// Cumulative allocations larger than the largest size class, each
    /// served by a page of its own.
    pub huge_allocations: u64,
    /// Cumulative bytes of those allocations.
    pub huge_bytes: u64,
    /// Resident set size of the process where mimalloc reads it (macOS);
    /// elsewhere mimalloc reports [`Self::committed_bytes`] here.
    pub resident_bytes: u64,
    /// Peak resident set size of the process.
    pub resident_peak_bytes: u64,
    /// Cumulative major page faults, those served from the backing store;
    /// the minor faults of first touching fresh memory are not counted (zero
    /// where the platform reports neither).
    pub page_faults: u64,
}

impl Stats {
    /// Reads the current statistics, or `None` if mimalloc could not produce them.
    pub fn read() -> Option<Self> {
        let mut buf = vec![0u8; 64 * 1024];
        // SAFETY: the buffer is writable for its full length and mimalloc
        // NUL-terminates what it writes, or returns NULL.
        let json = unsafe {
            let p = mi::mi_stats_get_json(buf.len(), buf.as_mut_ptr().cast());
            if p.is_null() {
                return None;
            }
            CStr::from_ptr(p).to_str().ok()?
        };
        Some(Self {
            reserved_bytes: current(json, "reserved"),
            pinned_bytes: PINNED_BYTES.load(Ordering::Relaxed),
            committed_bytes: scalar(json, "commit_current"),
            committed_peak_bytes: scalar(json, "commit_peak"),
            allocated_bytes: current(json, "malloc_normal") + current(json, "malloc_huge"),
            allocated_peak_bytes: peak(json, "malloc_normal") + peak(json, "malloc_huge"),
            purged_bytes: scalar(json, "purged"),
            purge_calls: scalar(json, "purge_calls"),
            arena_purges: scalar(json, "arena_purges"),
            mmap_calls: scalar(json, "mmap_calls"),
            commit_calls: scalar(json, "commit_calls"),
            pages: current(json, "pages"),
            threads: current(json, "threads"),
            arenas: scalar(json, "arena_count"),
            huge_allocations: scalar(json, "malloc_huge_count"),
            huge_bytes: total(json, "malloc_huge"),
            resident_bytes: scalar(json, "rss_current"),
            resident_peak_bytes: scalar(json, "rss_peak"),
            page_faults: scalar(json, "page_faults"),
        })
    }
}

/// Returns the text following `"key":` in `json`, or an empty string.
fn value<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\":");
    json.find(&needle)
        .map_or("", |at| json[at + needle.len()..].trim_start())
}

/// Parses the leading unsigned integer of `text`.
fn integer(text: &str) -> u64 {
    let digits = text.trim_start();
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    digits[..end].parse().unwrap_or(0)
}

/// A scalar field such as `"purged": 123`.
fn scalar(json: &str, key: &str) -> u64 {
    integer(value(json, key))
}

/// A sub-field of a count object such as `"pages": { "total": 1, "peak": 2, "current": 3 }`.
fn count(json: &str, key: &str, part: &str) -> u64 {
    let object = value(json, key);
    if !object.starts_with('{') {
        return 0;
    }
    let end = object.find('}').unwrap_or(object.len());
    scalar(&object[..end], part)
}

fn current(json: &str, key: &str) -> u64 {
    count(json, key, "current")
}

fn total(json: &str, key: &str) -> u64 {
    count(json, key, "total")
}

fn peak(json: &str, key: &str) -> u64 {
    count(json, key, "peak")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const RESERVE_BYTES: usize = 2 * ARENA_CHUNK_SIZE;
    const PURGE_DELAY: Duration = Duration::from_secs(3600);
    /// A limit off every slice boundary, so the conversion's rounding shows.
    const MAX_OBJECT: usize = ARENA_CHUNK_SIZE + 1;

    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc::new(Config {
        purge: Purge::After(PURGE_DELAY),
        reserve: Some(Reserve::pinned(RESERVE_BYTES)),
        transparent_huge_pages: Some(false),
        arena_max_object_size: Some(MAX_OBJECT),
        ..Config::DEFAULT
    });

    #[test]
    fn config_is_applied_before_use() {
        let status = GLOBAL.status();
        assert!(status.configured);
        assert_eq!(status.reserve, ReserveOutcome::Pinned);
        assert_eq!(OptionId::PurgeDelay.get(), 3_600_000);
        assert_eq!(OptionId::ArenaPurgeMult.get(), 1);
        assert_eq!(OptionId::AllowThp.get(), 0);
        let effective = Effective::read();
        assert_eq!(effective.purge, Some(PURGE_DELAY));
        assert!(effective.purge_decommits);
        assert!(!effective.transparent_huge_pages);
        #[cfg(target_os = "linux")]
        // SAFETY: this prctl takes integer arguments only.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_GET_THP_DISABLE, 0, 0, 0, 0), 1);
        }
        assert!(is_global_allocator());
        assert_eq!(version(), 30503);
        assert_eq!(good_size(4096), 4096);
        assert_eq!(good_size(4096 + 32), 5120);
    }

    #[test]
    fn purge_delay_is_bounded_and_mirrors_mimalloc() {
        assert_eq!(purge_millis(Duration::MAX), c_long::from(i32::MAX));
        assert_eq!(purge_millis(Duration::from_millis(5)), 5);
        assert_eq!(arena_purge_delay(1000, 4), Some(Duration::from_secs(4)));
        assert_eq!(arena_purge_delay(0, 4), Some(Duration::ZERO));
        assert_eq!(arena_purge_delay(-1, 4), None);
        assert_eq!(arena_purge_delay(1000, -1), None);
        assert_eq!(
            arena_purge_delay(c_long::MAX, 2),
            Some(Duration::from_millis(c_long::MAX as u64))
        );
    }

    #[test]
    fn arena_object_limit_rounds_up_and_is_bounded() {
        // Bytes round up to the KiB mimalloc stores, bounded so the value it
        // reads back in bytes fits the option type, and mimalloc rounds the
        // KiB up to a slice.
        assert_eq!(
            OptionId::ArenaMaxObjectSize.get(),
            (ARENA_CHUNK_SIZE / 1024 + 1) as c_long
        );
        assert_eq!(
            Effective::read().arena_max_object_size,
            ARENA_CHUNK_SIZE + ARENA_SLICE_SIZE
        );
        assert_eq!(size_option(usize::MAX), c_long::MAX / 1024);
    }

    #[test]
    fn constants_match_vendored_headers() {
        // Enumerators of `mi_option_t` number from zero in declaration order;
        // the legacy aliases at the end carry explicit values and are skipped.
        let header = include_str!("../../mimalloc/include/mimalloc.h");
        let body = header
            .split_once("typedef enum mi_option_e {")
            .and_then(|(_, rest)| rest.split_once("} mi_option_t;"))
            .map(|(body, _)| body)
            .expect("mimalloc.h must declare the mi_option_t enum");
        let mut value = -1;
        let ids: HashMap<&str, i32> = body
            .lines()
            .map(|line| {
                line.split("//")
                    .next()
                    .unwrap()
                    .trim()
                    .trim_end_matches(',')
            })
            .filter(|entry| !entry.is_empty() && !entry.contains('='))
            .map(|name| {
                value += 1;
                (name, value)
            })
            .collect();
        for (id, name) in [
            (OptionId::ArenaEagerCommit, "mi_option_arena_eager_commit"),
            (OptionId::PurgeDecommits, "mi_option_purge_decommits"),
            (
                OptionId::AllowLargeOsPages,
                "mi_option_allow_large_os_pages",
            ),
            (OptionId::PurgeDelay, "mi_option_purge_delay"),
            (OptionId::ArenaReserve, "mi_option_arena_reserve"),
            (OptionId::ArenaPurgeMult, "mi_option_arena_purge_mult"),
            (OptionId::AllowThp, "mi_option_allow_thp"),
            (
                OptionId::ArenaMaxObjectSize,
                "mi_option_arena_max_object_size",
            ),
        ] {
            assert_eq!(
                ids.get(name),
                Some(&(id as i32)),
                "{name} must carry its vendored mi_option_t value"
            );
        }

        let types = include_str!("../../mimalloc/include/mimalloc/types.h");
        let max_align: usize = types
            .lines()
            .find_map(|line| line.strip_prefix("#define MI_MAX_ALIGN_SIZE"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .expect("types.h must define MI_MAX_ALIGN_SIZE as an integer");
        assert_eq!(max_align, MALLOC_ALIGNMENT);
    }

    #[test]
    fn fast_paths_hand_out_aligned_memory() {
        // Both branches of every entry point hand out usable, correctly
        // aligned memory and accept each other's pointers on release. Several
        // live blocks per layout matter: consecutive blocks of a word-multiple
        // size class alternate between word and 16-byte alignment, so a single
        // allocation can look aligned by chance.
        for (size, align) in [
            (100usize, 1usize),
            (100, 8),
            (100, 16),
            (1, 16),
            (8, 16),
            (16, 16),
            (24, 16),
            (32, 16),
            (48, 16),
            (3, 8),
            (100, 64),
            (4096, 4096),
            (100, 4096),
        ] {
            let layout = Layout::from_size_align(size, align).expect("layout must be valid");
            // SAFETY: valid non-zero layouts; every pointer is freed below.
            unsafe {
                let mut live = Vec::new();
                for _ in 0..16 {
                    let a = GLOBAL.alloc(layout);
                    assert!(
                        !a.is_null() && (a as usize).is_multiple_of(align),
                        "the pointer must be non-null and aligned for {layout:?}"
                    );
                    let z = GLOBAL.alloc_zeroed(layout);
                    assert!(
                        !z.is_null() && (z as usize).is_multiple_of(align),
                        "the pointer must be non-null and aligned for {layout:?}"
                    );
                    assert!(std::slice::from_raw_parts(z, size).iter().all(|b| *b == 0));
                    live.push((a, z));
                }
                let grown = Layout::from_size_align(10_000, align).expect("layout must be valid");
                for (a, z) in live {
                    let r = GLOBAL.realloc(a, layout, grown.size());
                    assert!(
                        !r.is_null() && (r as usize).is_multiple_of(align),
                        "the pointer must be non-null and aligned for {layout:?}"
                    );
                    GLOBAL.dealloc(r, grown);
                    GLOBAL.dealloc(z, layout);
                }
            }
        }
    }

    #[test]
    fn realloc_shrink_keeps_alignment() {
        // Shrinking a 16-byte aligned block below the smallest 16-byte size
        // class must stay on the aligned reallocation path: the plain path
        // would hand out an 8-byte class block, which is 16-byte aligned
        // only every other block.
        let layout = Layout::from_size_align(48, 16).expect("layout must be valid");
        let shrunk = Layout::from_size_align(8, 16).expect("layout must be valid");
        // SAFETY: valid non-zero layouts; every pointer is freed below.
        unsafe {
            let live: Vec<*mut u8> = (0..16).map(|_| GLOBAL.alloc(layout)).collect();
            for p in live {
                let r = GLOBAL.realloc(p, layout, shrunk.size());
                assert!(
                    !r.is_null() && (r as usize).is_multiple_of(16),
                    "the pointer must be non-null and aligned for {shrunk:?}"
                );
                GLOBAL.dealloc(r, shrunk);
            }
        }
    }

    #[test]
    fn realloc_grows_into_the_exact_size_class() {
        // Growing a 16-byte aligned block to a size that is a multiple of 16
        // takes the plain reallocation path, so the moved block is its exact
        // size class and growing it by 16 more bytes moves it again. The
        // aligned path would pad the moved block by the alignment, landing it
        // in the next class with room for those bytes.
        let layout = Layout::from_size_align(4096, 16).expect("layout must be valid");
        let grown = Layout::from_size_align(8192, 16).expect("layout must be valid");
        let widened = Layout::from_size_align(8192 + 16, 16).expect("layout must be valid");
        // SAFETY: every pointer passed to realloc and dealloc came from GLOBAL
        // with the layout it was last allocated or resized to, the layouts are
        // valid and non-zero, and the block is freed below.
        unsafe {
            let p = GLOBAL.realloc(GLOBAL.alloc(layout), layout, grown.size());
            assert!(!p.is_null() && p.addr().is_multiple_of(16));
            let q = GLOBAL.realloc(p, grown, widened.size());
            assert!(!q.is_null() && q.addr().is_multiple_of(16));
            assert_ne!(q, p, "a block of its exact size class must move to grow");
            GLOBAL.dealloc(q, widened);
        }
    }

    #[test]
    fn stats_reflect_reservation_and_huge_allocations() {
        let before = Stats::read().expect("stats must be available");

        // The pinned reservation serves the tests' small working set, so the
        // only memory mimalloc maps itself is its page map, far below the
        // arena reserve size an automatic arena would add. The arena count is
        // not exactly one because another test in this process adds a second
        // pinned arena.
        assert!(before.pinned_bytes >= RESERVE_BYTES as u64);
        assert!(before.arenas >= 1);
        assert!(before.reserved_bytes < RESERVE_BYTES as u64);
        assert!(before.committed_bytes > 0);
        assert!(before.threads >= 1);

        let largest = vec![1u8; LARGE_OBJECT_LIMIT];
        let after = Stats::read().expect("stats must be available");
        assert_eq!(after.huge_allocations, before.huge_allocations);
        drop(largest);

        let size = LARGE_OBJECT_LIMIT + 1;
        let block = vec![1u8; size];
        let after = Stats::read().expect("stats must be available");
        assert!(after.huge_allocations > before.huge_allocations);
        assert!(after.huge_bytes >= before.huge_bytes + size as u64);
        assert!(after.allocated_bytes >= before.allocated_bytes + size as u64);
        drop(block);
        let released = Stats::read().expect("stats must be available");
        assert!(released.allocated_bytes < after.allocated_bytes);
    }

    #[test]
    fn reservations_are_trimmed_to_chunks() {
        let chunk = mi::mi_arena_min_size();
        assert_eq!(chunk, ARENA_CHUNK_SIZE);
        assert_eq!(whole_chunks(chunk - 1), None);
        assert_eq!(whole_chunks(chunk + chunk / 2), Some(chunk));
        assert_eq!(whole_chunks(usize::MAX), Some(usize::MAX / chunk * chunk));
        let before = PINNED_BYTES.load(Ordering::Relaxed);
        assert_eq!(manage_pinned(chunk, true), ReserveOutcome::Pinned);
        assert_eq!(PINNED_BYTES.load(Ordering::Relaxed) - before, chunk as u64);
    }

    #[test]
    fn parser_handles_scalars_and_count_objects() {
        let json = r#"{
  "process": { "rss_current": 10, "page_faults": 7 },
  "pages": { "total": 949, "peak": 631, "current": 630 },
  "pages_abandoned": { "total": 1, "peak": 1, "current": 1 },
  "purged": 83492864,
  "malloc_huge": { "total": 67108864, "peak": 67108864, "current": 0 },
  "malloc_bins": [ { "total": 1, "peak": 1, "current": 1, "block_size": 8 } ],
  "arena_count": 1
}"#;
        assert_eq!(scalar(json, "purged"), 83492864);
        assert_eq!(current(json, "pages"), 630);
        assert_eq!(total(json, "malloc_huge"), 67108864);
        assert_eq!(scalar(json, "arena_count"), 1);
        assert_eq!(scalar(json, "missing"), 0);
        assert_eq!(current(json, "purged"), 0);

        // A part missing from a count object is not found in a later object.
        assert_eq!(count(json, "malloc_huge", "block_size"), 0);
    }

    #[test]
    fn smallest_size_class_pages_stay_within_mimalloc_block_counts() {
        // mimalloc counts the blocks of a page in 16-bit fields. An 8-byte
        // class in a 512 KiB small page (`large-objects-4m`) stays below that
        // limit only because the page header at the start of the slice takes
        // a few blocks' worth of space. Fill more than one such page and check
        // every block was served and no page claims more blocks than it can
        // count.
        const COUNT: usize = u16::MAX as usize + 4096;
        let boxes: Vec<Box<u8>> = (0..COUNT).map(|i| Box::new(i as u8)).collect();
        let mut addresses: Vec<usize> = boxes.iter().map(|b| ptr::from_ref(&**b).addr()).collect();
        addresses.sort_unstable();
        addresses.dedup();
        assert_eq!(addresses.len(), COUNT);
        let mut blocks_per_page: HashMap<usize, usize> = HashMap::new();
        for address in &addresses {
            *blocks_per_page
                .entry(address / ARENA_SLICE_SIZE)
                .or_default() += 1;
        }
        assert!(
            blocks_per_page
                .values()
                .all(|count| *count <= u16::MAX as usize)
        );
        assert!(boxes.iter().enumerate().all(|(i, b)| **b == i as u8));
    }

    #[test]
    fn unpinned_and_default_configs_are_constructible() {
        let defaulted = MiMalloc::new(Config::DEFAULT);
        assert_eq!(defaulted.config(), &Config::default());
        assert!(!Reserve::unpinned(1).pinned);
    }

    #[test]
    fn configuration_is_process_wide() {
        // A second instance reports the process state and never applies its
        // own configuration: an allocation served through it leaves the
        // options GLOBAL applied in place.
        let other = MiMalloc::new(Config {
            purge: Purge::Never,
            ..Config::DEFAULT
        });
        assert_eq!(other.status(), GLOBAL.status());
        let layout = Layout::new::<u64>();
        // SAFETY: a valid non-zero layout, and the block is freed below.
        unsafe {
            let block = other.alloc(layout);
            assert!(!block.is_null());
            other.dealloc(block, layout);
        }
        assert_eq!(other.status(), GLOBAL.status());
        assert_eq!(OptionId::PurgeDelay.get(), 3_600_000);
    }
}
